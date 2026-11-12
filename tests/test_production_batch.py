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
    assert result['counts']['problem_files'] == 1
    failed = next(f for f in result['files'] if f['row'] == 3)
    assert failed['status'] == 'UPLOADED_URL_SAVE_FAILED'
    assert failed['remote_document_ids'] == [documents[1]['id']]
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


def same_number_batch(sample, *, second_day=6):
    documents = batch(sample, 2)
    *_, excel, pdf = sample
    book = load_workbook(excel)
    book.active['B3'] = datetime(2026, 10, second_day)
    book.active['E3'] = '123'
    book.save(excel)
    book.close()
    name = f'2026-10-{second_day:02d}-Синтетика-Б-123.pdf'
    (pdf / documents[1]['name']).rename(pdf / name)
    documents[1]['name'] = name
    return documents


def test_two_dates_same_number_upload_and_repeat(sample, https_mock):
    run, preview, tree, _, _, excel, _ = sample
    documents = same_number_batch(sample)
    before = preview('даты-превью')
    assert [f['category'] for f in before['files']] == ['MATCHED', 'MATCHED']
    https_mock.responses = [r for d in documents for r in responses(sample, d)]
    result = run('разные-даты')
    assert result['uploaded'] == result['urls_written'] == 2, result['errors']
    assert len(result['checkpoints']) == 2
    assert urls(excel) == [f"https://lk.sarex.io/documentations/{d['id']}" for d in documents]
    add_remote(tree, documents)
    repeated = run('повтор-дат')
    assert repeated['uploaded'] == repeated['urls_written'] == 0
    assert post_count(https_mock) == 8


def test_remote_other_day_does_not_block_independent_inspection(sample, https_mock):
    run, _, tree, _, _, excel, _ = sample
    documents = same_number_batch(sample)
    add_remote(tree, documents[:1])
    https_mock.responses = responses(sample, documents[1])
    result = run('один-уже-есть')
    assert result['uploaded'] == result['urls_written'] == 1
    assert urls(excel) == [None, f"https://lk.sarex.io/documentations/{documents[1]['id']}"]
    assert post_count(https_mock) == 4


def test_undated_remote_number_still_blocks_upload(sample, https_mock):
    run, _, tree, _, _, _, _ = sample
    documents = same_number_batch(sample)
    add_remote(tree, [{**documents[0], 'name': 'Синтетика-123.pdf'}])
    result = run('неизвестная-дата-сервера')
    assert result['uploaded'] == 0 and not post_count(https_mock)
    assert all('REMOTE_DOCUMENT_EXISTS' in f['reasons'] for f in result['files'])


def test_same_day_same_number_still_blocks_all(sample, https_mock):
    run = sample[0]
    same_number_batch(sample, second_day=5)
    result = run('одинаковая-дата')
    assert result['uploaded'] == 0 and not post_count(https_mock)
    assert all(f['category'] == 'AMBIGUOUS' for f in result['files'])


def test_legacy_key_recovers_url_and_accepts_another_day(sample, https_mock, monkeypatch):
    run, _, tree, document, _, excel, pdf = sample
    with monkeypatch.context() as old:
        # Simulate rc.9 writing its original key into a NEW disposable journal.
        old.setattr(scope, 'operation_key', scope.legacy_operation_key)
        old.setattr(flow, 'operation_key', scope.legacy_operation_key)

        def cannot_save(*args, **kwargs):
            raise ValidationError('Синтетический отказ сохранения ссылки')
        old.setattr(flow, 'commit_urls', cannot_save)
        https_mock.responses = responses(sample, document)
        first = run('старый-ключ')
        assert first['uploaded'] == 1 and first['urls_written'] == 0
    with Journal(scope.journal_path(), [pdf.parent]) as journal:
        old_key, = journal.checkpoints()
        old_payload = journal.operation(old_key)
    documents = same_number_batch(sample)
    add_remote(tree, documents[:1])
    https_mock.responses = (responses(sample, documents[0], repeat=True)
                            + responses(sample, documents[1]))
    result = run('старый-и-новый-ключи')
    assert result['already_confirmed'] == result['uploaded'] == 1, result['errors']
    assert result['urls_written'] == 2 and post_count(https_mock) == 8
    with Journal(scope.journal_path(), [pdf.parent]) as journal:
        assert len(journal.checkpoints()) == 2
        assert journal.operation(old_key) == old_payload
        assert scope.operation_key(old_payload) not in journal.checkpoints()
    assert urls(excel) == [f"https://lk.sarex.io/documentations/{d['id']}" for d in documents]
    add_remote(tree, documents)
    assert run('повтор-старого-и-нового')['uploaded'] == 0
    assert post_count(https_mock) == 8


def test_new_key_cannot_bypass_existing_legacy_intent(sample, https_mock, monkeypatch):
    run, _, _, document, _, _, pdf = sample
    with monkeypatch.context() as old:
        old.setattr(scope, 'operation_key', scope.legacy_operation_key)
        old.setattr(flow, 'operation_key', scope.legacy_operation_key)
        https_mock.responses = responses(sample, document)[:2] + [wire(status=403)]
        run('старое-намерение')
    with Journal(scope.journal_path(), [pdf.parent]) as journal:
        key, = journal.checkpoints()
        item = journal.operation(key)
        before = journal.checkpoints()
        with pytest.raises(ValidationError, match='ключ'):
            journal.register_production({scope.operation_key(item): item})
        assert journal.checkpoints() == before
    assert not post_count(https_mock)


def test_legacy_unknown_blocks_even_a_different_date(sample, https_mock, monkeypatch):
    run, _, _, document, _, _, pdf = sample
    with monkeypatch.context() as old:
        old.setattr(scope, 'operation_key', scope.legacy_operation_key)
        old.setattr(flow, 'operation_key', scope.legacy_operation_key)
        https_mock.responses = responses(sample, document)[:3] + [wire(status=500)]
        assert run('старый-unknown')['stopped']
    with Journal(scope.journal_path(), [pdf.parent]) as journal:
        before = journal.checkpoints()
        key, = before
        evidence = journal.response_candidates(key)
    same_number_batch(sample)
    with pytest.raises(ValidationError, match='OUTCOME_UNKNOWN'):
        run('другие-даты-при-unknown')
    with Journal(scope.journal_path(), [pdf.parent]) as journal:
        assert journal.checkpoints() == before
        assert journal.response_candidates(key) == evidence
    assert post_count(https_mock) == 1


def test_fill_two_dates_saves_exact_ids_and_repeat_is_empty(sample, tmp_path):
    from sarex_loader.recovery import run_recovery

    _, preview, tree, _, _, excel, _ = sample
    documents = same_number_batch(sample)
    add_remote(tree, documents)
    config = preview.config
    options = dict(tree_index=tree, read_tree=True, require_complete_children=True)
    plan = run_recovery(config, **options)
    assert plan['summary']['MATCHED'] == 2
    backups = tmp_path / 'резервные копии'
    backups.mkdir()
    result = run_recovery(config, **options, output_dir=tmp_path / 'fill-result',
                          write_original=True, backup_dir=backups,
                          expected_plan_sha256=plan['plan_sha256'])
    assert result['urls_written'] == 2
    assert urls(excel) == [f"https://lk.sarex.io/documentations/{d['id']}" for d in documents]
    repeat = run_recovery(config, **options)
    assert repeat['summary']['EXISTING_URL'] == 2 and not repeat['candidates']


@pytest.mark.parametrize('conflict', ['unknown_pdf_date', 'same_excel_day', 'duplicate_remote_day'])
def test_fill_dates_never_hide_unknown_or_ambiguous_candidates(sample, conflict):
    from sarex_loader.recovery import run_recovery

    _, preview, tree, _, _, _, _ = sample
    documents = same_number_batch(sample, second_day=5 if conflict == 'same_excel_day' else 6)
    if conflict == 'unknown_pdf_date':
        documents[0]['name'] = 'Синтетика-123.pdf'
    if conflict == 'duplicate_remote_day':
        documents.append({**documents[0], 'id': 9000010,
                          'path': documents[0]['path'].rsplit('.', 1)[0] + '.9000010',
                          'name': '2026-10-05-Синтетика-Копия-123.pdf'})
    add_remote(tree, documents)
    result = run_recovery(preview.config, tree_index=tree, read_tree=True,
                          require_complete_children=True)
    expected_ambiguous = 1 if conflict == 'duplicate_remote_day' else 2
    assert result['summary']['AMBIGUOUS'] == expected_ambiguous
    assert result['summary']['MATCHED'] == 2 - expected_ambiguous


def test_production_summary_and_plan_hash_reflect_content_error(sample, https_mock):
    run, _, _, _, _, _, pdf = sample
    documents = batch(sample, 2)
    (pdf / documents[1]['name']).write_bytes(b'%PDF-1.7\nMissing EOF\n')
    https_mock.responses = responses(sample, documents[0])
    result = run('ошибка-содержимого')
    assert result['uploaded'] == result['urls_written'] == 1
    assert result['counts']['problem_files'] == 1
    assert result['summary'] == {'UPLOADED_AND_SAVED': 1, 'UPLOAD_SKIPPED': 1}
    assert 'ready_to_upload' not in result['counts']
    approved = json.loads((pdf.parent.parent / 'ошибка-содержимого-approved-plan'
                           / 'plan.json').read_text())
    assert result['plan_sha256'] == approved['sha256']
    assert result['preview_plan_sha256'] != result['plan_sha256']
    successful = next(f for f in result['files'] if f['status'] == 'UPLOADED_AND_SAVED')
    assert successful['remote_document_ids'] == [documents[0]['id']]
    text = (pdf.parent.parent / 'ошибка-содержимого' / 'PDF_UPLOAD_PREVIEW.md').read_text()
    assert '| Проблемные файлы | 1 |' in text
    assert approved['sha256'] in text
