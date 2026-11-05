"""Isolated, durable mock acceptance workflow. No production CLI dispatch exists."""

import json
import os
import sqlite3
from pathlib import Path

from sarex_loader.api_models import ApiError, valid_id
from sarex_loader.config import checked_path
from sarex_loader.journal import fingerprint
from sarex_loader.messages import describe
from sarex_loader.monthly_folders import infer_month_name
from sarex_loader.process_lock import lock_file
from sarex_loader.safety import ValidationError

APP_ID = 1397115974


class FolderSimulationJournal:
    """Separate SQLite schema, never opens/migrates historical upload journals."""

    def __init__(self, path):
        path = Path(path).absolute()
        checked_path(path.parent, directory=True)
        if path.name != "folder-simulation.sqlite3":
            raise ValidationError("Нужен отдельный журнал симуляции папок.")
        new = not path.exists()
        if new:
            fd = os.open(
                path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600
            )
            os.close(fd)
        checked_path(path, directory=False)
        self.lock_fd = os.open(
            path.with_suffix(".lock"), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        try:
            lock_file(self.lock_fd)
        except OSError:
            os.close(self.lock_fd)
            raise ValidationError("Журнал папок уже используется другим процессом.") from None
        self.db = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=0)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA trusted_schema=OFF")
        if new:
            self.db.execute(f"PRAGMA application_id={APP_ID}")
            self.db.execute("CREATE TABLE folders (key TEXT PRIMARY KEY, state TEXT, data TEXT)")
            self.db.execute("CREATE TABLE events (key TEXT, state TEXT, data TEXT)")
            self.db.commit()
        elif self.db.execute("PRAGMA application_id").fetchone()[0] != APP_ID:
            self.db.close()
            os.close(self.lock_fd)
            raise ValidationError("Чужой журнал не открывается и не изменяется.")

    def state(self, key):
        row = self.db.execute("SELECT state FROM folders WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def record(self, key, state, data):
        encoded = json.dumps(data, ensure_ascii=True, sort_keys=True)
        self.db.execute(
            "INSERT INTO folders VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE "
            "SET state=excluded.state, data=excluded.data",
            (key, state, encoded),
        )
        self.db.execute("INSERT INTO events VALUES (?, ?, ?)", (key, state, encoded))
        self.db.commit()

    def close(self):
        self.db.close()
        os.close(self.lock_fd)


def create_missing_months(
    plans, *, client, journal, answer, simulate=False, creation_enabled=False
):
    """Runs after existing-folder uploads in mock acceptance only; no upload callback.

    `client` must be a non-network test adapter. Production requires a separately
    accepted completeness contract, locked journal and integration approval.
    """
    if simulate is not True or getattr(client, "network_enabled", True) is not False:
        raise ValidationError("Создание папок пока доступно только в изолированной симуляции.")
    if answer not in ("да", "нет"):
        raise ValidationError("Введите «да» или «нет».")
    outcomes, cache = [], {}
    for plan in plans:
        key = fingerprint({k: plan[k] for k in ("disk_id", "parent_id", "month")})
        prior = journal.state(key)
        if prior in ("IN_FLIGHT", "OUTCOME_UNKNOWN"):
            outcomes.append({**plan, "status": "OUTCOME_UNKNOWN"})
            break
        if prior == "CREATED":
            outcomes.append({**plan, "status": "CREATED", "replayed": False})
            continue
        if answer == "нет":
            journal.record(key, "DECLINED", plan)
            outcomes.append({**plan, "status": "DECLINED"})
            continue
        if creation_enabled is not True:
            journal.record(key, "FOLDER_CREATION_DISABLED", plan)
            outcomes.append({**plan, "status": "FOLDER_CREATION_DISABLED"})
            continue
        parent = plan["parent_id"]
        if not valid_id(parent):
            raise ValidationError("Недопустимый ID родителя.")
        if parent not in cache:
            cache[parent] = client.read_children(parent)
        evidence = cache[parent]
        if (
            evidence.get("complete") is not True
            or evidence.get("fresh") is not True
            or evidence.get("parent_path") != plan.get("parent_path")
            or not plan.get("parent_path")
            or plan["parent_path"][-1] != parent
        ):
            outcomes.append({**plan, "status": "TREE_COMPLETENESS_UNVERIFIED"})
            continue
        naming = infer_month_name(
            evidence["children"], plan["month"], parent_id=parent, parent_path=plan["parent_path"]
        )
        if naming["status"] != "MONTH_NAME_INFERRED" or naming["name"] != plan["name"]:
            outcomes.append({**plan, "status": naming["status"]})
            continue
        # Persist BEFORE sending. A crash here is uncertain and never auto-replayed.
        journal.record(key, "IN_FLIGHT", plan)
        created = None
        try:
            created = client.create_month_folder(
                disk_id=plan["disk_id"], parent_id=parent, name=plan["name"]
            )
            journal.record(key, "IN_FLIGHT", {**plan, "candidate_id": created.id})
            verified = client.get_document(created.id)
            expected_path = ".".join(map(str, (*plan["parent_path"], created.id)))
            if (
                not valid_id(created.id)
                or verified.id != created.id
                or verified.name != plan["name"]
                or not verified.is_folder
                or verified.disk_id != plan["disk_id"]
                or verified.path != expected_path
            ):
                raise ValueError("Результат создания не подтверждён.")
        except ApiError as exc:
            # Only an explicit 403 before a candidate is safe to classify as denied.
            denied = exc.status == 403 and not exc.outcome_unknown and created is None
            state = "FORBIDDEN" if denied else "OUTCOME_UNKNOWN"
            journal.record(key, state, plan)
            outcomes.append({**plan, "status": state})
            if not denied:
                break
        except Exception:
            journal.record(key, "OUTCOME_UNKNOWN", plan)
            outcomes.append({**plan, "status": "OUTCOME_UNKNOWN"})
            break
        else:
            journal.record(key, "CREATED", {**plan, "folder_id": verified.id})
            outcomes.append({**plan, "status": "CREATED", "folder_id": verified.id})
    for item in outcomes:
        item["description"] = describe(item["status"])
    all_created = bool(outcomes) and all(r["status"] == "CREATED" for r in outcomes)
    return {
        "simulation": True,
        "outcomes": outcomes,
        "upload_into_created_folders": False,
        "message": (
            "Папки созданы. Повторно запустите программу той же командой "
            "для загрузки оставшихся PDF"
            if all_created
            else "Проверьте созданные и не созданные папки. Загрузка в новые папки "
            "в текущем запуске не выполняется."
        ),
    }


def finish_mock_upload(
    plans, *, upload_existing, client, journal, ask=input, tell=print, creation_enabled=False
):
    """Acceptance harness: existing upload phase, then one prompt, then stop."""
    if getattr(client, "network_enabled", True) is not False:
        raise ValidationError("Разрешён только изолированный тестовый транспорт.")
    upload_result = upload_existing()
    if upload_result.get("outcome_unknown"):
        return {"message": describe("OUTCOME_UNKNOWN"), "outcomes": []}
    if not plans:
        return {"message": "Отсутствующих месячных папок нет.", "outcomes": []}
    tell("Не найдены необходимые папки:")
    for plan in plans:
        tell(plan["full_path"])
    result = create_missing_months(
        plans,
        client=client,
        journal=journal,
        answer=ask("Создать отсутствующие папки? (да/нет) "),
        simulate=True,
        creation_enabled=creation_enabled,
    )
    for item in result["outcomes"]:
        tell(item["full_path"] + ": " + item["description"])
    tell(result["message"])
    return result
