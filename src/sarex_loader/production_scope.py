"""Explicit SK/VK upload scope, separate from every historical 99-Test exception."""

import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from sarex_loader.api_models import parse_document
from sarex_loader.folder_resolver import safe_component
from sarex_loader.journal import BATCH_CONFIRMATION_POLICY, fingerprint
from sarex_loader.recursive_gateway import PROFILE_ROOTS
from sarex_loader.safety import ValidationError
from sarex_loader.single_test_scope import TEST_DISK_ID

CONTEXT = {"mode": "production-ledger-v1", "disk_id": TEST_DISK_ID}


def journal_path():
    # Independent of account, current workbook/path, extraction directory and tree hash.
    # Never fall back to a new path on a lock, malformed file or unknown result.
    return Path.home() / ".sarex-loader-production-journal"


def legacy_operation_key(item):
    """Read compatibility only: never rewrite or re-key existing journal rows."""
    return fingerprint(
        {
            "profile": item["registry_type"],
            "number": item["number"],
            "disk_id": TEST_DISK_ID,
            "mode": CONTEXT["mode"],
        }
    )


def operation_key(item):
    try:
        day = date.fromisoformat(item["bundle_date"][:10]).isoformat()
    except (KeyError, TypeError, ValueError):
        raise ValidationError("Для ключа инспекции нужна корректная дата Excel.") from None
    return fingerprint({"inspection": legacy_operation_key(item), "date": day, "version": 2})


def stored_identity_keys(operations):
    """Index old/new keys without changing any persisted payload or checkpoint."""
    identities = {}
    for key, item in operations.items():
        validate_item(item)
        identity = operation_key(item)
        if key not in {identity, legacy_operation_key(item)} or identity in identities:
            raise ValidationError("Неоднозначные ключи рабочего журнала; нужна ручная сверка.")
        identities[identity] = key
    return identities


def validate_item(item):
    profile = item.get("registry_type")
    root = PROFILE_ROOTS.get(profile, (None,))[0]
    path = item.get("resolved_path_ids", [])
    if (
        item.get("mode") != "production-upload-v1"
        or item.get("status") != "LOCAL_MATCH"
        or item.get("confirmation_policy") != BATCH_CONFIRMATION_POLICY
        or root is None
        or item.get("target_folder_id") != str(root)
        or item.get("disk_id") != TEST_DISK_ID
        or type(path) is not list
        or not path
        or any(type(i) is not int or i < 1 for i in path)
        or len(path) != len(set(path))
        or root not in path
        or path[-1] == root
        or any(
            i in path for i in {2093037, *[r[0] for p, r in PROFILE_ROOTS.items() if p != profile]}
        )
        or path[-1] != item.get("resolved_folder_id")
        or not safe_component(item.get("filename", ""))
        or not item["filename"].lower().endswith(".pdf")
        or not isinstance(item.get("number"), str)
        or not item["number"]
        or not re.fullmatch("[0-9a-f]{64}", item.get("pdf_sha256", ""))
        or item.get("document_type") != "pdf"
        or item.get("file_key") != "pdf"
    ):
        raise ValidationError("Рабочий PDF или назначение не прошли проверку области загрузки.")
    return root, tuple(path)


@dataclass(frozen=True)
class ProductionScope:
    root_id: int
    root_path: tuple
    approved: dict
    plan_sha256: str

    def validate(self, journal, key):
        if (
            journal.path != journal_path()
            or fingerprint(self.approved) != self.plan_sha256
            or key not in self.approved
            or journal.operation(key) != self.approved[key]
        ):
            raise ValidationError("Рабочий план или журнал изменён после подтверждения.")
        root, path = validate_item(journal.operation(key))
        if root != self.root_id or path[: len(self.root_path)] != self.root_path:
            raise ValidationError("Папка находится вне выбранного корня.")
        if any(c["state"] == "OUTCOME_UNKNOWN" for c in journal.checkpoints().values()):
            raise ValidationError("OUTCOME_UNKNOWN: новые POST запрещены.")
        return path[-1], path

    def verify_root(self, value):
        doc = parse_document(value)
        if (
            doc.id != self.root_id
            or not doc.is_folder
            or doc.path != ".".join(map(str, self.root_path))
            or doc.name
            != next(name for root, name in PROFILE_ROOTS.values() if root == self.root_id)
        ):
            raise ValidationError("GET не подтвердил выбранный рабочий корень.")
        from sarex_loader.single_test_scope import check_disk

        check_disk(doc.disk_id)
