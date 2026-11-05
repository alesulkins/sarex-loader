"""Fixed-scope, name-free summary of an already parsed Gateway response."""

from typing import Literal, TypedDict

from sarex_loader.gateway_models import GatewayDocuments, GatewaySearchDocument

GATEWAY_DISK_ID = '25cb6f03-454d-4bc6-aeb6-2808c3a2b68b'
GATEWAY_FOLDER_ID = 6272634
GATEWAY_TARGET_ID = 6316681

TargetResult = Literal[
    'FOUND_DIRECT', 'FOUND_NESTED', 'FOUND_OUTSIDE_FOLDER', 'NOT_PRESENT_IN_RESPONSE',
]


class GatewaySummary(TypedDict):
    status: Literal['GATEWAY_RESPONSE_VALIDATED']
    documents_count: int
    folder_id: int
    direct_count: int
    nested_count: int
    target_id: int
    target_result: TargetResult
    server_completeness_verified: bool


def summarize_gateway(result: GatewayDocuments[GatewaySearchDocument], *,
                      folder_id=GATEWAY_FOLDER_ID, target_id=GATEWAY_TARGET_ID) -> GatewaySummary:
    descendants = result.descendants_of(folder_id)
    target_result: TargetResult = 'NOT_PRESENT_IN_RESPONSE'
    for document in result.documents:
        if document.id == target_id:
            path = document.path_ids
            if len(path) > 1 and path[-2] == folder_id:
                target_result = 'FOUND_DIRECT'
            elif folder_id in path[:-1]:
                target_result = 'FOUND_NESTED'
            else:
                target_result = 'FOUND_OUTSIDE_FOLDER'
            break
    return {
        'status': 'GATEWAY_RESPONSE_VALIDATED', 'documents_count': len(result.documents),
        'folder_id': folder_id, 'direct_count': len(descendants.direct),
        'nested_count': len(descendants.nested), 'target_id': target_id,
        'target_result': target_result, 'server_completeness_verified': False,
    }
