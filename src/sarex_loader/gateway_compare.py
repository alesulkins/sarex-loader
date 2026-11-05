"""Bounded GET comparison. Agreement is evidence, never a completeness contract."""

import json
import time
from datetime import UTC, datetime
from types import MappingProxyType

from sarex_loader.api_client import _read_response_body, _tls_context
from sarex_loader.api_models import ApiError
from sarex_loader.api_transport import GetRequest
from sarex_loader.gateway_tree import gateway_login
from sarex_loader.gateway_tree_policy import GatewayTreeReadPolicy
from sarex_loader.https_transport import ReadOnlyHTTPSTransport
from sarex_loader.read_only_policy import DOCUMENTATION_BASE, ReadOnlyPolicy


def read_metadata(policy, url, access):
    """Never issue POST, follow redirects, retry or retain private headers/error bodies."""
    started = time.monotonic()
    response = None
    result = {"http_status": None, "error": None}
    data = None
    try:
        request = GetRequest(
            url,
            MappingProxyType(
                {
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Authorization": access.header_value(),
                }
            ),
            _tls_context(),
            policy.timeouts.connect,
            policy.timeouts.read,
            started + policy.timeouts.total,
        )
        response = ReadOnlyHTTPSTransport(policy, confirmed=True).open(request)
        result["http_status"] = response.status
        result["pagination_headers"] = {
            k: v
            for k, v in response.headers.items()
            if k
            in ("link", "x-total-count", "content-range", "x-next-page", "x-page", "x-per-page")
        }
        if response.status == 200:
            raw = _read_response_body(
                response, policy.max_response_bytes, policy.timeouts, request.deadline
            )
            result["response_bytes"] = len(raw)
            data = json.loads(raw)
            result["top_level_keys"] = sorted(data) if isinstance(data, dict) else []
        else:
            result["error"] = "HTTP_" + str(response.status)
    except ApiError as exc:
        result["error"] = exc.code.value
    except (ValueError, TypeError):
        result["error"] = "INVALID_JSON"
    finally:
        if response is not None:
            response.close()
    result["seconds"] = round(time.monotonic() - started, 3)
    return result, data


def compare_children(gateway, document, parent):
    """Expose missing/empty child arrays separately from a proven empty directory."""
    direct = [
        d
        for d in gateway.get("documents", [])
        if str(d.get("path", "")).split(".")[-2:-1] == [str(parent)]
    ]
    result = {
        "gateway_total_objects": len(gateway.get("documents", [])),
        "gateway_direct_count": len(direct),
        "parts": {},
    }
    for field, folder in (("files", False), ("folders", True)):
        gateway_ids = {d["id"] for d in direct if d.get("is_folder") is folder}
        values = document.get(field)
        valid = isinstance(values, list) and all(type(i) is int and i > 0 for i in values)
        doc_ids = set(values) if valid else set()
        result["parts"][field] = {
            "gateway_count": len(gateway_ids),
            "documentations_count": len(values) if valid else None,
            "documentations_array_valid": valid,
            "documentations_duplicate_ids": len(values) - len(doc_ids) if valid else None,
            "ids_equal": gateway_ids == doc_ids if valid else None,
            "gateway_only_ids": sorted(gateway_ids - doc_ids) if valid else [],
            "documentations_only_ids": sorted(doc_ids - gateway_ids) if valid else [],
        }
    result["completeness_proven"] = False
    return result


def compare_folders(disk_id, folder_ids):
    # Policy validates bounded IDs before authentication.
    docs_policy = ReadOnlyPolicy(tuple(folder_ids), max_response_bytes=8 * 1024**2)
    policies = [GatewayTreeReadPolicy(disk_id, i) for i in docs_policy.document_ids]
    result = {
        "started_at": datetime.now(UTC).isoformat(),
        "resource_mutations": 0,
        "get_count": 0,
        "folders": [],
        "completeness_proven": False,
    }
    with gateway_login() as token:
        for policy in policies:
            folder = policy.folder_id
            gw_info, gw = read_metadata(policy, policy.url, token())
            doc_info, doc = read_metadata(
                docs_policy, DOCUMENTATION_BASE + f"/v1/documents/{folder}", token()
            )
            result["get_count"] += 2
            entry = {"folder_id": folder, "gateway": gw_info, "documentations": doc_info}
            if isinstance(gw, dict) and isinstance(doc, dict):
                entry["documentations_is_requested_folder"] = (
                    doc.get("id") == folder and doc.get("is_folder") is True
                )
                if entry["documentations_is_requested_folder"]:
                    entry.update(compare_children(gw, doc, folder))
                    entry["name"] = doc.get("name")
            result["folders"].append(entry)
    result["finished_at"] = datetime.now(UTC).isoformat()
    return result
