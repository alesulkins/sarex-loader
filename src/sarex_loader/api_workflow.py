"""One PDF mock workflow, with in-memory checkpoints only. Not a production uploader."""

import threading
from enum import Enum
from pathlib import Path

from sarex_loader.api_client import SarexClient
from sarex_loader.api_models import ApiError, ApiErrorCode, valid_id
from sarex_loader.api_upload_models import BundleDraft
from sarex_loader.multipart import MultipartPDF
from sarex_loader.safety import ValidationError


class Phase(Enum):
    NEW = 'NEW'
    TYPES_CHECKED = 'TYPES_CHECKED'
    BUNDLE_CREATED = 'BUNDLE_CREATED'
    FILE_SENT = 'FILE_SENT'
    FINISHED = 'FINISHED'
    ATTACHED = 'ATTACHED'
    UNKNOWN = 'OUTCOME_UNKNOWN'


class MockUploadSession:
    def __init__(self, client: SarexClient, draft: BundleDraft, input_root: Path, pdf: Path, *,
                 parent_id: int | None = None, document_id: int | None = None):
        if ((parent_id is None) == (document_id is None)
                or not valid_id(parent_id if parent_id is not None else document_id)):
            raise ValidationError('Укажите ровно одну целевую папку или существующий документ.')
        with MultipartPDF(input_root, pdf) as body:
            if draft.filename != body.filename:
                raise ValidationError('Имя Bundle должно точно совпадать с выбранным PDF.')
            self.sha256 = body.sha256
        self._client, self._draft, self._root, self._pdf = client, draft, input_root, pdf
        self._parent_id, self._document_id = parent_id, document_id
        self._lock = threading.Lock()
        self.phase = Phase.NEW
        self.last_confirmed = Phase.NEW
        self.bundle_id: str | None = None
        self.document_id: int | None = document_id

    def step(self) -> Phase:
        if not self._lock.acquire(blocking=False):
            raise ApiError(ApiErrorCode.OUTCOME_UNKNOWN)
        try:
            if self.phase == Phase.UNKNOWN:
                raise ApiError(ApiErrorCode.OUTCOME_UNKNOWN, outcome_unknown=True)
            if self.phase == Phase.ATTACHED:
                return self.phase
            is_write = self.phase != Phase.NEW
            try:
                self._advance()
            except BaseException:
                if is_write:
                    self.phase = Phase.UNKNOWN
                raise
            self.last_confirmed = self.phase
            return self.phase
        finally:
            self._lock.release()

    def _advance(self) -> None:
        client, draft = self._client, self._draft
        if self.phase == Phase.NEW:
            matches = [field for kind in client.get_document_types()
                       if kind.name == draft.document_type for field in kind.fields
                       if field.key == draft.key
                       and field.file is True and field.can_upload is True]
            if len(matches) != 1:
                raise ApiError(ApiErrorCode.INVALID_RESPONSE)
            self.phase = Phase.TYPES_CHECKED
        elif self.phase == Phase.TYPES_CHECKED:
            # Check again before creating a remote artifact, even in a mock workflow.
            with MultipartPDF(self._root, self._pdf, expected_sha256=self.sha256):
                pass
            self.bundle_id = client.create_bundle(draft).id
            self.phase = Phase.BUNDLE_CREATED
        elif self.phase == Phase.BUNDLE_CREATED:
            with MultipartPDF(self._root, self._pdf, expected_sha256=self.sha256) as body:
                client.upload_single(self.bundle_id, draft.key, body)
            self.phase = Phase.FILE_SENT
        elif self.phase == Phase.FILE_SENT:
            client.upload_finish(self.bundle_id)
            self.phase = Phase.FINISHED
        elif self.phase == Phase.FINISHED:
            if self._parent_id is not None:
                result = client.create_document(disk_id=draft.disk_id, parent_id=self._parent_id,
                                                name=draft.filename, bundle_id=self.bundle_id)
                self.document_id = result.id
            else:
                client.add_bundle(self._document_id, self.bundle_id)
            self.phase = Phase.ATTACHED
