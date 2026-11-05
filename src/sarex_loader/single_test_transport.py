"""One-purpose HTTPS adapter: fixed test target, fixed PDF, durable intent and ordered requests.

It shares the TLS/socket implementation, NOT the read-only adapter's permissions.
No endpoint/parent/disk/body can be supplied through a policy object.
"""

import copy
import hashlib
import json
import re
import threading
import time
from pathlib import Path

from sarex_loader.api_client import Timeouts, _read_response_body, _status_error
from sarex_loader.api_models import ApiError, ApiErrorCode, decode_payload, parse_document, valid_id
from sarex_loader.api_transport import GetRequest, JsonBody, PostRequest
from sarex_loader.api_upload_models import BundleDraft, parse_bundle, parse_types, path_id
from sarex_loader.bundle_diagnostics import (
    document_bundle_observation,
    error_response_shape,
    request_shape,
    response_content_type,
    upload_status_observation,
)
from sarex_loader.https_transport import ReadOnlyHTTPSTransport, checked_request_headers
from sarex_loader.journal import BATCH_DOCUMENT_STATES, Journal, batch_document_policy, fingerprint
from sarex_loader.read_only_policy import DOCUMENTATION_BASE, ReadOnlyPolicy
from sarex_loader.response_shape import json_type, shape, validation_issue
from sarex_loader.safety import ValidationError
from sarex_loader.single_test_config import SingleTestConfig, single_journal_path
from sarex_loader.single_test_identity import EXCEL_OPERATION_ID
from sarex_loader.single_test_predecessor import (
    independent_journal_path,
    predecessor_guard,
    predecessor_reference,
)
from sarex_loader.single_test_scope import (
    TEST_DISK_ID,
    TEST_PARENT_ID,
    TEST_PATH_IDS,
    TEST_ROOT_ID,
    verify_created_document,
    verify_pdf_type,
    verify_root_document,
    verify_target_document,
)
from sarex_loader.single_test_trace import reason
from sarex_loader.synthetic_pdf import SyntheticPDF, synthetic_pdf_bytes

PHASES = {'PLANNED': 'CREATE_BUNDLE', 'BUNDLE_CREATED': 'UPLOAD_SINGLE',
          'FILE_SENT': 'UPLOAD_FINISH', 'FINISHED': 'CREATE_DOCUMENT'}


def batch_journal_path():
    # One durable ledger for the prepared batch manifest; no CLI replacement path.
    return Path(__file__).resolve().parents[2] / '.batch-test-journal'


def single_plan(config, *, upload_context=None):
    payload = {'mode': 'single-synthetic-test-v1', 'disk_id': TEST_DISK_ID,
               'parent_id': TEST_PARENT_ID, 'root_id': TEST_ROOT_ID, 'path_ids': TEST_PATH_IDS,
               'draft': config.draft().payload(),
               'pdf_sha256': hashlib.sha256(synthetic_pdf_bytes(config.operation_id)).hexdigest()}
    if config.operation_id is not None:
        payload.update(mode='single-independent-test-v1', operation_id=config.operation_id,
                       predecessor=predecessor_reference(config.operation_id))
    if upload_context is not None:
        # Different Excel/rules cannot reuse an existing request checkpoint. Legacy
        # single-test keys stay unchanged; no migration or journal replacement.
        payload['upload_context'] = copy.deepcopy(upload_context)
    key = fingerprint(payload)
    return payload, key, {key: {'status': 'LOCAL_MATCH', **payload}}


class _Replay:
    def __init__(self, body):
        self._body = body
        self.status = 200
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(body))}

    def read(self, max_bytes, *, timeout):
        part, self._body = self._body[:max_bytes], self._body[max_bytes:]
        return part

    def close(self):
        self._body = b''


class SingleTestHTTPSTransport(ReadOnlyHTTPSTransport):
    """Exact-type opt-in from SarexClient is required. Default construction is disarmed."""

    def __init__(self, config: SingleTestConfig, journal: Journal, *, confirmed=False,
                 upload_context=None):
        self._batch = self._batch_url_only = self._acceptance = False
        self._parent_id, self._path_ids = TEST_PARENT_ID, TEST_PATH_IDS
        self._batch_document_policy = False
        if type(config) is not SingleTestConfig or type(journal) is not Journal:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        config.draft()  # Includes the closed allowlist of operation identities.
        if config.operation_id == EXCEL_OPERATION_ID and upload_context is None:
            raise ValidationError('EXCEL_BOUND_PLAN_REQUIRED')
        if config.operation_id == EXCEL_OPERATION_ID and not journal.checkpoints():
            raise ValidationError('EXCEL_PLAN_REGISTRATION_REQUIRED')
        if upload_context is not None and config.operation_id is None \
                and journal.path != single_journal_path():
            raise ValidationError('SINGLE_JOURNAL_PATH_MISMATCH')
        if config.operation_id is not None:
            if journal.path != independent_journal_path(config.operation_id):
                raise ValidationError('INDEPENDENT_JOURNAL_PATH_MISMATCH')
            with predecessor_guard(config.operation_id):
                pass  # Fail closed even for direct client/transport use outside the CLI.
        super().__init__(ReadOnlyPolicy((TEST_PARENT_ID, TEST_ROOT_ID)), confirmed=confirmed)
        # Check historical intents BEFORE comparing the new plan. A corrected disk
        # changes its fingerprint; that must never obscure or bypass an unknown POST.
        if any(item['state'] not in {'PLANNED', 'ATTACHED'}
               for item in journal.checkpoints().values()):
            raise ValidationError(
                'OUTCOME_UNKNOWN_OR_PARTIAL_TEST: нужна ручная сверка; POST запрещён.')
        self._upload_context = copy.deepcopy(upload_context)
        context, self._key, operations = single_plan(config, upload_context=upload_context)
        journal.register(context, operations)  # Refuses any different plan, even in this same DB.
        checkpoint = journal.checkpoint(self._key)
        self._phase = checkpoint['state']
        if self._phase not in {'PLANNED', 'ATTACHED'}:
            raise ValidationError(
                'OUTCOME_UNKNOWN_OR_PARTIAL_TEST: нужна ручная сверка; POST запрещён.')
        self._journal, self._config = journal, config
        self._bundle, self._document = checkpoint['bundle_id'], checkpoint['document_id']
        if self._phase != 'PLANNED':
            path_id(self._bundle)
        if self._phase == 'ATTACHED' and (
                not valid_id(self._document) or self._document in TEST_PATH_IDS):
            raise ValidationError('Некорректный ID в журнале одиночного теста.')
        self.timeouts = Timeouts()
        self.max_response_bytes, self.max_requests = 1024**2, 8
        self._preflight = [f'/v1/documents/{self._parent_id}', f'/v1/documents/{TEST_ROOT_ID}']
        if self._phase != 'ATTACHED':
            self._preflight.append('/v1/documents/types')
        self._cursor = 0
        self._target_checked_at = None
        self._failed = False
        self._outer_lock = threading.Lock()
        self._response_diagnostic = {}

    @classmethod
    def for_batch(cls, journal, key, *, confirmed=False, url_only=False, document_only=False,
                  acceptance=False, customer_test=False, production=None):
        """Reuse the exact adapter, TLS, ordering and candidate capture for one batch item."""
        parent, path_ids, ledger = TEST_PARENT_ID, TEST_PATH_IDS, batch_journal_path()
        root = TEST_ROOT_ID
        if (type(acceptance) is not bool or type(customer_test) is not bool
                or acceptance and customer_test):
            raise ValidationError('Неверный тестовый режим.')
        if acceptance:
            from sarex_loader.acceptance_scope import journal_path, manifest, validate_item
            from sarex_loader.journal import fingerprint

            ledger = journal_path()
            if type(journal) is not Journal or len(journal.checkpoints()) != 2:
                raise ValidationError('Тест ограничен двумя операциями.')
            names = set()
            for operation_key in journal.checkpoints():
                operation = journal.operation(operation_key)
                validate_item(operation)
                if fingerprint(operation) != operation_key:
                    raise ValidationError('Тестовый ключ операции изменён.')
                names.add(operation['filename'])
            if names != {f['filename'] for f in manifest()['files']}:
                raise ValidationError('Нужны две разные разрешённые тестовые операции.')
            parent, path_ids = validate_item(journal.operation(key))
        if customer_test:
            from sarex_loader.customer_test_scope import (
                journal_path,
                validate_item,
                validate_journal,
            )

            if type(journal) is not Journal:
                raise ValidationError('Нужен SQLite-журнал теста.')
            validate_journal(journal)
            ledger = journal_path()
            parent, path_ids = validate_item(journal.operation(key))
        if production is not None:
            from sarex_loader.production_scope import ProductionScope, journal_path

            if type(production) is not ProductionScope or acceptance or customer_test:
                raise ValidationError('Нельзя смешивать рабочую и тестовую области.')
            parent, path_ids = production.validate(journal, key)
            root, ledger = production.root_id, journal_path()
        if (cls is not SingleTestHTTPSTransport or type(journal) is not Journal
                or journal.path != ledger or type(url_only) is not bool
                or type(document_only) is not bool or document_only and not url_only):
            raise ValidationError('BATCH_JOURNAL_REQUIRED')
        item = journal.operation(key)
        if (not (item.get('mode') == 'batch-test-v1' or batch_document_policy(item))
                or item.get('status') != 'LOCAL_MATCH'
                or item.get('disk_id') != TEST_DISK_ID
                or item.get('resolved_folder_id') != parent
                or tuple(item.get('resolved_path_ids', ())) != path_ids
                or not re.fullmatch('[0-9a-f]{64}', item.get('pdf_sha256', ''))):
            raise ValidationError('BATCH_TARGET_NOT_AUTHORIZED')
        checkpoint = journal.checkpoint(key)
        state = checkpoint['state']
        identifier = checkpoint['document_id']
        if url_only and state == 'OUTCOME_UNKNOWN':
            candidates = [c['document_id'] for c in journal.response_candidates(key)
                          if c['phase'] == 'CREATE_DOCUMENT']
            identifier = candidates[0] if len(candidates) == 1 else None
        if (state not in {'PLANNED', 'ATTACHED', *BATCH_DOCUMENT_STATES} and not (
                url_only and state == 'OUTCOME_UNKNOWN' and valid_id(identifier))
                or url_only and not valid_id(identifier)
                or not url_only and any(c['state'] not in {
                    'PLANNED', 'BLOCKED', 'ATTACHED', *BATCH_DOCUMENT_STATES}
                    for c in journal.checkpoints().values())
                or state == 'PLANNED' and any(c['state'] == 'DOCUMENT_CREATED'
                                             for c in journal.checkpoints().values())):
            raise ValidationError('BATCH_RECONCILIATION_REQUIRED')
        self = cls.__new__(cls)
        ReadOnlyHTTPSTransport.__init__(
            self, ReadOnlyPolicy((parent, root)), confirmed=confirmed)
        self._batch, self._batch_url_only = True, document_only
        self._acceptance = acceptance
        self._customer_test = customer_test
        self._production = production
        self._root_id = root
        self._parent_id, self._path_ids = parent, path_ids
        self._batch_document_policy = batch_document_policy(item) and state != 'OUTCOME_UNKNOWN'
        self._config = BundleDraft(TEST_DISK_ID, item['document_type'], item['file_key'],
                                   item['filename'], item['bundle_date'])
        self._pdf_sha256 = item['pdf_sha256']
        self._upload_context = item
        self._journal, self._key = journal, key
        self._phase = 'ATTACHED' if url_only else state
        self._bundle, self._document = checkpoint['bundle_id'], identifier
        self.timeouts = Timeouts()
        self.max_response_bytes, self.max_requests = 1024**2, 8
        self._preflight = [f'/v1/documents/{self._parent_id}', f'/v1/documents/{root}']
        if self._phase == 'PLANNED':
            self._preflight.append('/v1/documents/types')
        self._cursor = 0
        self._target_checked_at = None
        self._failed = False
        self._outer_lock = threading.Lock()
        self._response_diagnostic = {}
        return self

    @property
    def response_diagnostic(self):
        return copy.deepcopy(self._response_diagnostic)

    @property
    def policy(self):
        return self

    def _next(self):
        if self._cursor < len(self._preflight):
            return 'GET', self._preflight[self._cursor]
        if self._phase == 'PLANNED':
            return 'POST', '/v1/bundles'
        if self._phase == 'BUNDLE_CREATED':
            return 'POST', f'/v1/bundles/{self._bundle}/{self._config.key}/upload_single'
        if self._phase == 'FILE_SENT':
            return 'POST', f'/v1/bundles/{self._bundle}/upload_finish'
        if self._phase == 'FINISHED':
            return 'POST', '/v1/documents'
        if self._phase in {'ATTACHED', *BATCH_DOCUMENT_STATES}:
            return 'GET', f'/v1/documents/{self._document}'
        raise ApiError(ApiErrorCode.ACCESS_DENIED)

    def authorize(self, method, url):
        if not self._confirmed or self._failed:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        expected_method, route = self._next()
        if type(method) is not str or type(url) is not str \
                or (method, url) != (expected_method, DOCUMENTATION_BASE + route):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        if method == 'POST' and getattr(self, '_production', None) is not None:
            self._production.validate(self._journal, self._key)
        if method == 'POST' and getattr(self, '_customer_test', False):
            from sarex_loader.customer_test_scope import validate_journal

            validate_journal(self._journal)
        if method == 'POST' and self._acceptance:
            from sarex_loader.acceptance_scope import journal_path, validate_item

            parent, path_ids = validate_item(self._journal.operation(self._key))
            if (self._journal.path != journal_path() or parent != self._parent_id
                    or path_ids != self._path_ids):
                raise ApiError(ApiErrorCode.ACCESS_DENIED)
        if method == 'POST' and (self._target_checked_at is None
                                 or time.monotonic() - self._target_checked_at > 60):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        return 'api.sarex.io', '/documentations/api' + route, False

    def _document_body(self):
        return {'disk_id': TEST_DISK_ID, 'parent_id': self._parent_id, 'is_folder': False,
                'name': self._config.filename, 'bundle_id': self._bundle}

    def _validate(self, request):
        if type(request) not in (GetRequest, PostRequest):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        host, path, _ = self.authorize(request.method, request.url)
        body_object = request.body if type(request) is PostRequest else None
        headers = checked_request_headers(request, has_body=body_object is not None)
        if request.method == 'GET':
            return host, path, None, headers
        checkpoint = self._journal.checkpoint(self._key)
        if (checkpoint['state'] != 'IN_FLIGHT' or checkpoint['phase'] != PHASES[self._phase]
                or checkpoint['bundle_id'] != self._bundle
                or checkpoint['document_id'] != self._document):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        if self._batch and self._phase == 'BUNDLE_CREATED':
            from sarex_loader.multipart import MultipartPDF

            if (type(body_object) is not MultipartPDF
                    or body_object.sha256 != self._pdf_sha256
                    or body_object.filename != self._config.filename
                    or headers['Content-Length'] != str(body_object.content_length)
                    or headers['Content-Type'] != body_object.content_type):
                raise ApiError(ApiErrorCode.ACCESS_DENIED)
            return host, path, body_object.iter_chunks(), headers
        if self._phase == 'FILE_SENT':
            if body_object is not None:
                raise ApiError(ApiErrorCode.ACCESS_DENIED)
            return host, path, None, headers
        if (self._phase == 'BUNDLE_CREATED' and type(body_object) is not SyntheticPDF
                or self._phase != 'BUNDLE_CREATED' and type(body_object) is not JsonBody):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        if (type(body_object.content_length) is not int
                or not 1 <= body_object.content_length <= 8192
                or headers['Content-Length'] != str(body_object.content_length)
                or headers['Content-Type'] != body_object.content_type):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        chunks = bytearray()
        for chunk in body_object.iter_chunks():
            if type(chunk) is not bytes or len(chunks) + len(chunk) > 8192:
                raise ApiError(ApiErrorCode.ACCESS_DENIED)
            chunks.extend(chunk)
        body = bytes(chunks)
        if len(body) != body_object.content_length or not body_object.complete:
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        if self._phase == 'BUNDLE_CREATED':
            match = re.fullmatch(r'multipart/form-data; boundary=(sarex-single-[0-9a-f]{32})',
                                 headers['Content-Type'])
            if match is None:
                raise ApiError(ApiErrorCode.ACCESS_DENIED)
            boundary = match[1]
            expected = ((f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                         f'filename="{self._config.filename}"\r\n'
                         'Content-Type: application/pdf\r\n\r\n')
                        .encode() + synthetic_pdf_bytes(self._config.operation_id)
                        + f'\r\n--{boundary}--\r\n'.encode())
            if body != expected:
                raise ApiError(ApiErrorCode.ACCESS_DENIED)
        else:
            draft = self._config if self._batch else self._config.draft()
            expected = (draft.payload() if self._phase == 'PLANNED'
                        else self._document_body())
            if headers['Content-Type'] != 'application/json' or decode_payload(body) != expected:
                raise ApiError(ApiErrorCode.ACCESS_DENIED)
            if self._phase == 'PLANNED':
                # Only emit the known path/keys AFTER the actual request body passed validation.
                self._response_diagnostic.update(request_shape(expected))
        return host, path, body, headers

    def _accept(self, value):
        if self._cursor < len(self._preflight):
            route = self._preflight[self._cursor]
            if route.endswith('/types'):
                verify_pdf_type(parse_types(value), self._config)
            elif route.endswith(str(self._parent_id)):
                verify_target_document(parse_document(value), expected_path=self._path_ids)
                self._target_checked_at = time.monotonic()
            else:
                if getattr(self, '_production', None) is not None:
                    self._production.verify_root(value)
                else:
                    verify_root_document(parse_document(value))
            self._cursor += 1
            return
        if self._phase in {'PLANNED', 'FILE_SENT'}:
            bundle = parse_bundle(value)
            if bundle.document_id is not None:
                raise ValidationError('UNEXPECTED_DOCUMENT_ATTACHMENT')
            if self._phase == 'FILE_SENT' and (
                    bundle.id != self._bundle or bundle.upload_status != 'uploaded'):
                raise ValidationError('BUNDLE_FINISH_NOT_CONFIRMED')
            if self._phase == 'PLANNED':
                if bundle.upload_status not in (None, 'created'):
                    raise ValidationError('UNEXPECTED_BUNDLE_STATUS')
                if self._batch and (bundle.id == 'ff8537eb-9b1f-455f-acc8-6b17fe0f3354' or any(
                        k != self._key and c['bundle_id'] == bundle.id
                        for k, c in self._journal.checkpoints().items())):
                    raise ValidationError('BATCH_BUNDLE_ID_REUSED')
                self._bundle, self._phase = bundle.id, 'BUNDLE_CREATED'
            else:
                self._phase = 'FINISHED'
        elif self._phase == 'BUNDLE_CREATED':
            self._phase = 'FILE_SENT'
        elif self._phase in {'FINISHED', 'ATTACHED', *BATCH_DOCUMENT_STATES}:
            document = parse_document(value)
            identifier = document.id if self._phase == 'FINISHED' else self._document
            if self._batch and (identifier == 7978396 or any(
                    k != self._key and c['document_id'] == identifier
                    for k, c in self._journal.checkpoints().items())):
                raise ValidationError('BATCH_DOCUMENT_ID_REUSED')
            verify_created_document(document, identifier, require_path=self._phase != 'FINISHED',
                                    expected_filename=self._config.filename,
                                    expected_path=self._path_ids)
            if (self._acceptance or getattr(self, '_production', None) is not None) and (
                    self._phase != 'FINISHED'):
                if value.get('type') != 'pdf':
                    raise ValidationError('Тип созданного документа не подтверждён GET.')
                self._response_diagnostic['verified_document'] = {
                    'id': document.id, 'name': document.name, 'type': value['type'],
                    'path': document.path, 'is_folder': document.is_folder,
                    'parent_id': self._parent_id,
                }
            if 'parent_id' in value and (type(value['parent_id']) is not int
                                         or value['parent_id'] != self._parent_id):
                raise ValidationError('TEST_DOCUMENT_PARENT_MISMATCH')
            # Document validity and Bundle association are separate facts. Null is
            # a valid projection, but must not silently confirm an attachment.
            self._response_diagnostic['document_checks_passed'] = True
            self._response_diagnostic.update(document_bundle_observation(
                value, self._bundle, identifier))
            if (self._batch_document_policy and 'bundles' in value
                    and value['bundles'] is None):
                # A successful CREATE response establishes Document identity, not a Bundle link.
                # The journal records DOCUMENT_CREATED; only a subsequent exact GET grants URL.
                if self._phase == 'FINISHED':
                    self._document, self._phase = identifier, 'DOCUMENT_CREATED'
                else:
                    self._phase = 'VERIFIED'
                return
            if self._batch_url_only and value.get('bundles') is None:
                # Explicit document-only URL policy; journal remains UNKNOWN if it was UNKNOWN.
                self._phase = 'VERIFIED'
                return
            if self._upload_context is not None and 'bundles' not in value:
                raise ValidationError('TEST_DOCUMENT_BUNDLE_UNCONFIRMED')
            if 'bundles' in value:
                bundles = value['bundles']
                if bundles is None:
                    raise ValidationError('TEST_DOCUMENT_BUNDLE_UNCONFIRMED')
                if type(bundles) is not list or len(bundles) != 1:
                    raise ValidationError('TEST_DOCUMENT_BUNDLE_MISMATCH')
                linked = parse_bundle(bundles[0])
                if (linked.id != self._bundle or linked.document_id not in (None, identifier)
                        or linked.upload_status not in (None, 'uploaded')):
                    raise ValidationError('TEST_DOCUMENT_BUNDLE_MISMATCH')
            if self._phase == 'FINISHED':
                self._document, self._phase = identifier, 'ATTACHED'
            else:
                self._phase = 'VERIFIED'

    def open(self, request):
        if not self._outer_lock.acquire(blocking=False):
            raise ApiError(ApiErrorCode.ACCESS_DENIED)
        response = None
        stage = (('GET_TARGET', 'GET_TEST_ROOT', 'GET_TYPES')[self._cursor]
                 if self._cursor < len(self._preflight)
                 else PHASES.get(self._phase, 'GET_CREATED_DOCUMENT'))
        diagnostic = self._response_diagnostic = {
            'stage': stage, 'http_status': None, 'phase': 'REQUEST', 'json_type': 'unavailable'}
        if stage == 'CREATE_BUNDLE':
            diagnostic.update(response_content_type=None, response_category='NOT_RECEIVED')
        try:
            # This check also prevents calling the generic socket implementation before preflight.
            self.authorize(request.method, request.url)
            single = request.url.endswith('/upload_single')
            response = super().open(request)
            diagnostic.update(http_status=response.status, phase='HTTP_STATUS')
            if stage == 'CREATE_BUNDLE':
                diagnostic['response_content_type'] = response_content_type(response, request)
                diagnostic['response_category'] = 'BODY_NOT_CLASSIFIED'
            error = _status_error(response.status)
            if error:
                if stage == 'CREATE_BUNDLE':
                    diagnostic.update(error_response_shape(
                        response, diagnostic['response_content_type'],
                        deadline=request.deadline, read_timeout=self.timeouts.read))
                raise error
            diagnostic['phase'] = 'BODY_AND_HEADERS'
            if single:
                total = 0
                while chunk := response.read(65536, timeout=self.timeouts.read):
                    total += len(chunk)
                    if total > self.max_response_bytes or time.monotonic() >= request.deadline:
                        raise ApiError(ApiErrorCode.RESPONSE_TOO_LARGE)
                value = None
            else:
                raw = _read_response_body(
                    response, self.max_response_bytes, self.timeouts, request.deadline)
                diagnostic['phase'] = 'JSON_DECODE'
                value = decode_payload(raw)
                raw = b''
                if stage in {'CREATE_BUNDLE', 'UPLOAD_FINISH', 'CREATE_DOCUMENT'}:
                    # Durable evidence is independent of model/scope acceptance and
                    # survives response.close(), later parsing or checkpoint failures.
                    diagnostic['phase'] = 'RECORD_CANDIDATES'
                    self._journal.record_response_candidates(self._key, stage, value)
                if stage == 'CREATE_BUNDLE':
                    diagnostic['response_category'] = 'JSON_' + json_type(value).upper()
                    # Observation cannot authorize a phase or precede durable ID capture.
                    diagnostic.update(upload_status_observation(value, request))
            kind = ('types' if stage == 'GET_TYPES' else 'bundle'
                    if stage in {'CREATE_BUNDLE', 'UPLOAD_FINISH'} else 'document')
            if not single:
                diagnostic.update(shape(value, kind))
                diagnostic['phase'] = 'MODEL'
                diagnostic.update(validation_issue(value, kind) or {'reason': 'OK'})
            response.close()
            response = None
            self._accept(value)  # State may advance ONLY from our own validated HTTPS response.
            diagnostic['reason'] = 'OK'
            return _Replay(json.dumps(value).encode())
        except BaseException as error:
            self._failed = True  # No retry/fallback after any uncertain outcome on this session.
            if diagnostic.get('reason') in (None, 'OK'):
                diagnostic['reason'] = ('INVALID_JSON' if diagnostic['phase'] == 'JSON_DECODE'
                                        else reason(error))
            if stage == 'CREATE_BUNDLE' and diagnostic['phase'] == 'JSON_DECODE':
                diagnostic['response_category'] = 'INVALID_JSON'
            if isinstance(error, ApiError) and diagnostic['http_status'] is None:
                diagnostic['http_status'] = error.status
            if isinstance(error, ValidationError):
                diagnostic['phase'] = 'SCOPE'
                raise ApiError(ApiErrorCode.INVALID_RESPONSE) from None
            raise
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    self._failed = True
            self._outer_lock.release()
