"""Both production profiles over fake HTTPS; never contacts Sarex or customer inputs."""

import json
from contextlib import contextmanager
from datetime import datetime

import pytest
from openpyxl import Workbook, load_workbook

from sarex_loader import folder_ledger
from sarex_loader import production_scope as scope
from sarex_loader import production_upload as flow
from sarex_loader.api_transport import BearerToken
from sarex_loader.audit import HEADERS
from sarex_loader.folder_resolver import FolderResolver
from sarex_loader.journal import Journal
from sarex_loader.recovery_config import parse_recovery_config
from sarex_loader.recursive_gateway import PROFILE_ROOTS
from sarex_loader.safety import ValidationError
from sarex_loader.synthetic_pdf import synthetic_pdf_bytes
from sarex_loader.tree_source import add_response
from sarex_loader.upload_preview import run_full_preview
from sarex_loader.user_settings import UserSettings
from tests.test_api_client import forbid_network as forbid_network
from tests.test_https_transport import https_mock as https_mock
from tests.test_https_transport import wire


@pytest.fixture(params=["sk", "vk"])
def sample(tmp_path, monkeypatch, request):
    kind = request.param
    source = tmp_path / "исходные"
    source.mkdir()
    pdf = source / "PDF"
    pdf.mkdir()
    excel = source / "реестр.xlsx"
    book = Workbook()
    book.active.title = "Тест"
    book.active.append(HEADERS)
    book.active.append(
        [1, datetime(2026, 10, 5), "Синтетический офис", "Синтетическая компания", "123", None]
    )
    book.save(excel)
    book.close()
    name = "2026-10-05-Синтетика-123.pdf"
    (pdf / name).write_bytes(synthetic_pdf_bytes())
    root, root_name = PROFILE_ROOTS[kind]
    path = [1600045, 2062798, root, 500, 501, 502, 503]
    names = [root_name, "Офис", "Компания", "Инспекции", "2026-10"]
    nodes = [
        {"id": i, "name": n, "is_folder": True, "path": ".".join(map(str, path[: p + 3]))}
        for p, (i, n) in enumerate(zip(path[2:], names, strict=True))
    ]
    tree = FolderResolver()
    raw = json.dumps({"documents": nodes}).encode()
    for n in nodes:
        add_response(tree, raw, 1024**2, queried_folder=n["id"])
    tree.observation = {
        "version": 3,
        "source": "gateway",
        "root_ids": [root],
        "traversal_status": "COMPLETED_OBSERVED_TREE",
        "root_verified": True,
        "unvisited_folder_ids": [],
        "global_error": None,
        "failed_folders": {},
        "context_names": {},
        "completeness_description": "Синтетический обход",
        "queried_at": {str(i): "2026-10-05T12:00:00+00:00" for i in tree.queried_folders},
    }
    config = parse_recovery_config(
        {
            "mode": "tree-recovery",
            "input_root": str(source),
            "filename_separator": "-",
            "url_contract_confirmed": True,
            "tree": {
                "source": "gateway",
                "disk_id": scope.TEST_DISK_ID,
                "root_ids": [root],
                "traversal": "recursive",
            },
            "registries": [
                {
                    "excel": excel.name,
                    "inspection_type": kind,
                    "root_id": str(root),
                    "office_folders": {"Синтетический офис": "Офис"},
                    "contractor_folders": {"Синтетическая компания": "Компания"},
                    "inspection_folder": "Инспекции",
                }
            ],
        }
    )
    monkeypatch.setattr(scope, "journal_path", lambda: tmp_path / "постоянный журнал")
    monkeypatch.setattr(flow, "journal_path", scope.journal_path)
    monkeypatch.setattr(folder_ledger, "journal_path", lambda: tmp_path / "журнал папок")

    @contextmanager
    def login():
        yield lambda: BearerToken("SYNTHETIC-TOKEN")

    monkeypatch.setattr(flow, "gateway_login", login)
    monkeypatch.setattr(flow, "fresh_children", lambda *args: tree.children[503])

    def preview(label):
        return run_full_preview(
            config,
            {kind: [pdf]},
            tmp_path / (label + "-preview"),
            flat=True,
            plan_moves=True,
            tree_index=tree,
        )

    def run(label, answer="да"):
        return flow.run(
            config,
            tree,
            preview(label),
            pdf,
            excel,
            tmp_path / label,
            UserSettings("synthetic", "synthetic"),
            ask=lambda _: answer,
        )

    preview.config = config
    payload = {
        "id": 9000001,
        "name": name,
        "is_folder": False,
        "path": ".".join(map(str, [*path, 9000001])),
        "disk_id": scope.TEST_DISK_ID,
        "bundles": None,
        "type": "pdf",
    }
    return run, preview, tree, payload, nodes, excel, pdf


def sequence(sample, *, repeat=False):
    _, _, _, doc, nodes, _, _ = sample
    prefix = [wire(nodes[-1]), wire(nodes[0])]
    if repeat:
        return [*prefix, wire(doc)]
    return [
        *prefix,
        wire(
            {
                "types": [
                    {
                        "name": "pdf",
                        "fields": [{"key": "pdf", "file": True, "can_be_uploaded_by_user": True}],
                    }
                ]
            }
        ),
        wire({"id": "synthetic-bundle", "document_id": None, "upload_status": "created"}),
        wire(body=b""),
        wire({"id": "synthetic-bundle", "upload_status": "uploaded"}),
        wire(doc),
        wire(doc),
    ]


def post_count(https_mock):
    return sum(bytes(s.sent).startswith(b"POST ") for s in https_mock.sockets)


def test_load_save_original_repeat_no_post(sample, https_mock):
    run, _, _, _, _, excel, _ = sample
    https_mock.responses = sequence(sample)
    result = run("первый")
    assert result["uploaded"] == result["urls_written"] == 1, result["errors"]
    assert not result["stopped"] and post_count(https_mock) == 4
    book = load_workbook(excel)
    assert book.active["F2"].value.endswith("/9000001")
    book.close()
    repeated = run("повторный")
    assert repeated["uploaded"] == repeated["urls_written"] == 0
    assert post_count(https_mock) == 4


def test_decline_no_post_no_original_change(sample, https_mock):
    run, _, _, _, _, excel, _ = sample
    before = excel.read_bytes()
    result = run("отмена", "нет")
    assert result["cancelled"] and not post_count(https_mock)
    assert excel.read_bytes() == before


def test_unknown_never_replays(sample, https_mock):
    run = sample[0]
    https_mock.responses = sequence(sample)[:3] + [wire(status=500)]
    result = run("сбой")
    assert result["stopped"] and post_count(https_mock) == 1
    with pytest.raises(ValidationError, match="OUTCOME_UNKNOWN"):
        run("повтор")
    assert post_count(https_mock) == 1


def test_excel_failure_recovers_url_without_upload(sample, https_mock, monkeypatch):
    run, _, tree, doc, _, _, _ = sample
    original = flow.commit_urls

    def fail(*args, **kwargs):
        raise ValidationError("Синтетический отказ записи Excel")

    monkeypatch.setattr(flow, "commit_urls", fail)
    https_mock.responses = sequence(sample)
    result = run("без-ссылки")
    assert result["stopped"] and result["urls_written"] == 0 and post_count(https_mock) == 4
    add_response(tree, json.dumps({"documents": [doc]}).encode(), 1024**2)
    monkeypatch.setattr(flow, "commit_urls", original)
    https_mock.responses = sequence(sample, repeat=True)
    result = run("восстановление")
    assert result["already_confirmed"] == result["urls_written"] == 1, result["errors"]
    assert post_count(https_mock) == 4


def test_missing_number_only_moves_after_consent(sample, https_mock):
    run, _, _, _, _, _, pdf = sample
    missing = pdf / "2026-10-05-Синтетика-999.pdf"
    missing.write_bytes(synthetic_pdf_bytes() + b"\n% another PDF\n")
    run("отмена", "нет")
    assert missing.exists() and not (pdf / "не найдено").exists()
    https_mock.responses = sequence(sample)
    result = run("отправка")
    assert result["uploaded"] == 1, result["errors"]
    assert not missing.exists() and (pdf / "не найдено" / missing.name).exists()


def test_changed_intent_cannot_use_new_key(sample, https_mock):
    run, _, _, _, _, _, pdf = sample
    https_mock.responses = sequence(sample)[:2] + [wire(status=403)]
    run("первый")  # blocked GET, PLANNED intent is retained
    (file,) = pdf.iterdir()
    file.write_bytes(synthetic_pdf_bytes() + b"\n% changed\n")
    result = run("изменённый")
    assert result["uploaded"] == 0 and not post_count(https_mock)
    with Journal(scope.journal_path(), [pdf.parent]) as journal:
        assert len(journal.checkpoints()) == 1


def test_repeated_number_different_dates_uses_correct_excel_row(sample):
    _, preview, _, _, _, excel, _ = sample
    book = load_workbook(excel)
    book.active.append([2, datetime(2026, 9, 22), 'Другой офис', 'Другой подрядчик', '123', None])
    book.save(excel)
    book.close()
    report = preview('повтор-номера-разные-даты')
    file = report['files'][0]
    assert file['category'] == 'MATCHED'
    assert file['row'] == 2
    assert file['folder_id'] == 503
    assert file['ready_by_metadata']
    assert not file['candidate_date_checks']
    assert not file['filename_route_checks']


def test_repeated_number_same_day_different_time_stays_blocked(sample):
    _, preview, _, _, _, excel, _ = sample
    book = load_workbook(excel)
    book.active.append([2, datetime(2026, 10, 5, 19),
                        'Другой офис', 'Другой подрядчик', '123', None])
    book.save(excel)
    book.close()
    file = preview('повтор-номера-одинаковый-день')['files'][0]
    assert file['category'] == 'AMBIGUOUS'
    assert file['folder_id'] is None
    assert not file['ready_by_metadata']
