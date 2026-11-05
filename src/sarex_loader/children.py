"""Bounded display of a validated Document response, without traversal or I/O."""

from typing import Literal, TypedDict

from sarex_loader.api_models import ApiError, ApiErrorCode, Document

CHILD_IDS_LIMIT = 20  # Per category; not configurable from untrusted input.


class ChildrenSummary(TypedDict):
    status: Literal['CHILDREN_RESPONSE_VALIDATED']
    id: int
    files_count: int
    folders_count: int
    total_count: int
    files: list[int]
    folders: list[int]
    files_truncated: bool
    folders_truncated: bool
    server_completeness_verified: bool


def summarize_children(document: Document) -> ChildrenSummary:
    """Accept only parsed folder metadata; counts describe this response, not server totals."""
    if (document.is_folder is not True or document.files is None
            or document.folders is None):
        # An omitted array is not proof of an empty folder. Never guess or query children.
        raise ApiError(ApiErrorCode.INVALID_RESPONSE)
    files_count, folders_count = len(document.files), len(document.folders)
    return {
        'status': 'CHILDREN_RESPONSE_VALIDATED', 'id': document.id,
        'files_count': files_count, 'folders_count': folders_count,
        'total_count': files_count + folders_count,
        'files': list(document.files[:CHILD_IDS_LIMIT]),
        'folders': list(document.folders[:CHILD_IDS_LIMIT]),
        'files_truncated': files_count > CHILD_IDS_LIMIT,
        'folders_truncated': folders_count > CHILD_IDS_LIMIT,
        'server_completeness_verified': False,
    }
