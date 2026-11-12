"""Current production entry point, synthetic multi-PDF batches, no real network/history."""

import json
from contextlib import contextmanager
from datetime import datetime

import pytest
from openpyxl import load_workbook

from sarex_loader import production_scope as scope
from sarex_loader import production_upload as flow
from sarex_loader.journal import Journal
from sarex_loader.safety import ValidationError
from sarex_loader.tree_source import add_response
from tests.test_api_client import forbid_network as forbid_network
from tests.test_https_transport import https_mock as https_mock
from tests.test_production_upload import post_count, sequence, wire
from tests.test_production_upload import sample as sample


def batch(sample, count):
    _, _, _, document, _, excel, pdf = sample
    template = (pdf / document['name']).read_bytes()
    documents = [document]
    book = load_workbook(excel)
    for i in range(1, count):
        number = str(123 + i)
        book.active.append([i + 1, datetime(2026, 10, 5), 'Синтетический офис',
                            'Синтетическая компания', number, None])
        name = f'2026-10-05-Синтетика-{number}.pdf'
        # Distinct inert comments, retaining valid xref offsets and EOF envelope.
        (pdf / name).write_bytes(template.replace(b'%%EOF', f'% Fixture {i}\n%%EOF'.encode()))
        identifier = document['id'] + i
        documents.append({**document, 'name': name, 'id': identifier,
                          'path': document['path'].rsplit('.', 1)[0] + f'.{identifier}'})
    book.save(excel)
    book.close()
    return documents


def responses(sample, document, *, repeat=False):
    local = list(sample)
    local[3] = document
    result = sequence(local, repeat=repeat)
    if not repeat:
        bundle = f"synthetic-bundle-{document['id']}"
        result[3] = wire({'id': bundle, 'document_id': None, 'upload_status': 'created'})
        result[5] = wire({'id': bundle, 'upload_status': 'uploaded'})
    return result


def add_remote(tree, documents):
    add_response(tree, json.dumps({'documents': documents}).encode(), 1024**2)


def urls(excel):
    book = load_workbook(excel)
    try:
        return [book.active.cell(r, 6).value for r in range(2, book.active.max_row + 1)]
    finally:
        book.close()


@pytest.mark.parametrize('count', [2, 9])
def test_batch_upload_all_urls_and_repeat_without_post(sample, https_mock, count):
    run, _, tree, _, _, excel, pdf = sample
    documents = batch(sample, count)
    before_pdf = {p.name: p.read_bytes() for p in pdf.iterdir()}
    https_mock.responses = [r for doc in documents for r in responses(sample, doc)]
    result = run('партия')
    assert result['uploaded'] == result['urls_written'] == count, result['errors']
    assert not result['stopped'] and not result['errors']
    assert post_count(https_mock) == 4 * count
    assert urls(excel) == [f"https://lk.sarex.io/documentations/{d['id']}" for d in documents]
    assert all(r['disk_verified'] for r in result['receipts'])
    assert all('upload.example.invalid' not in u for u in urls(excel))
    with Journal(scope.journal_path(), [pdf.parent]) as journal:
        assert len(journal.checkpoints()) == count
        assert {c['document_id'] for c in journal.checkpoints().values()} == {
            d['id'] for d in documents}
    add_remote(tree, documents)
    repeated = run('повтор-партии')
    assert repeated['uploaded'] == repeated['urls_written'] == 0
    assert post_count(https_mock) == 4 * count
    assert {p.name: p.read_bytes() for p in pdf.iterdir()} == before_pdf
    assert not https_mock.responses


def test_batch_excel_failure_reconciles_then_continues(sample, https_mock, monkeypatch):
    run, _, tree, _, _, excel, _ = sample
    documents = batch(sample, 3)
    commit = flow.commit_urls
    calls = []

    def fail_second(*args, **kwargs):
        calls.append(True)
        if len(calls) == 2:
            raise ValidationError('Синтетический отказ записи Excel второго PDF')
        return commit(*args, **kwargs)

    monkeypatch.setattr(flow, 'commit_urls', fail_second)
    https_mock.responses = [r for d in documents[:2] for r in responses(sample, d)]
    result = run('сбой-второй-ссылки')
    assert result['stopped'] and result['urls_written'] == 1
    assert post_count(https_mock) == 8
    assert urls(excel) == [f"https://lk.sarex.io/documentations/{documents[0]['id']}", None, None]
    add_remote(tree, documents[:2])
    monkeypatch.setattr(flow, 'commit_urls', commit)
    https_mock.responses = (responses(sample, documents[1], repeat=True)
                            + responses(sample, documents[2]))
    result = run('продолжение-после-сбоя')
    assert result['already_confirmed'] == 1 and result['uploaded'] == 1, result['errors']
    assert result['urls_written'] == 2 and not result['stopped']
    assert post_count(https_mock) == 12
    assert urls(excel) == [f"https://lk.sarex.io/documentations/{d['id']}" for d in documents]


def test_batch_unknown_second_post_never_replayed(sample, https_mock):
    run, _, _, _, _, excel, pdf = sample
    documents = batch(sample, 3)
    https_mock.responses = (responses(sample, documents[0])
                            + responses(sample, documents[1])[:3] + [wire(status=500)])
    result = run('неопределенный-второй')
    assert result['stopped'] and post_count(https_mock) == 5
    assert urls(excel)[1:] == [None, None]
    with Journal(scope.journal_path(), [pdf.parent]) as journal:
        before = journal.checkpoints()
        assert sum(c['state'] == 'OUTCOME_UNKNOWN' for c in before.values()) == 1
    with pytest.raises(ValidationError, match='OUTCOME_UNKNOWN'):
        run('повтор-неопределенного')
    assert post_count(https_mock) == 5
    with Journal(scope.journal_path(), [pdf.parent]) as journal:
        assert journal.checkpoints() == before


def test_batch_invalid_later_excel_target_blocks_before_first_post(sample, https_mock, monkeypatch):
    run, _, _, _, _, excel, _ = sample
    batch(sample, 2)
    before = excel.read_bytes()
    prepare = flow.prepare_operations

    def invalid_later_target(*args):
        operations, selected = prepare(*args)
        list(selected.values())[-1]['excel_candidates'][0]['id'] = 'incorrect-row-id'
        return operations, selected

    monkeypatch.setattr(flow, 'prepare_operations', invalid_later_target)
    with pytest.raises(ValidationError, match='Строка изменена'):
        run('неверная-вторая-строка')
    assert not post_count(https_mock)
    assert excel.read_bytes() == before


def test_zero_uploads_move_only_preserves_excel(sample, https_mock):
    run, _, _, document, _, excel, pdf = sample
    source = pdf / document['name']
    missing = source.with_name('2026-10-05-Синтетика-999.pdf')
    source.rename(missing)
    before = excel.read_bytes()
    result = run('только-перемещение')
    assert result['uploaded'] == result['urls_written'] == 0
    assert len(result['moves']) == 1 and not post_count(https_mock)
    assert (pdf / 'не найдено' / missing.name).exists() and not missing.exists()
    assert excel.read_bytes() == before


def test_batch_cooperative_stop_and_resume(sample, https_mock, monkeypatch):
    run, _, tree, _, _, excel, _ = sample
    documents = batch(sample, 3)

    @contextmanager
    def stop_after_first():
        calls = []

        def stopped():
            calls.append(True)
            return len(calls) > 1
        yield stopped

    original = flow.stop_after_file
    monkeypatch.setattr(flow, 'stop_after_file', stop_after_first)
    https_mock.responses = responses(sample, documents[0])
    result = run('штатная-остановка')
    assert result['stopped'] and result['uploaded'] == result['urls_written'] == 1
    assert post_count(https_mock) == 4
    add_remote(tree, documents[:1])
    monkeypatch.setattr(flow, 'stop_after_file', original)
    https_mock.responses = [r for d in documents[1:] for r in responses(sample, d)]
    result = run('возобновление')
    assert not result['stopped'] and result['uploaded'] == result['urls_written'] == 2
    assert post_count(https_mock) == 12
    assert urls(excel) == [f"https://lk.sarex.io/documentations/{d['id']}" for d in documents]
