"""Local opt-in and actual folder POST workflow over fake HTTPS; no Sarex network."""

import json
from contextlib import contextmanager
from datetime import datetime
from types import SimpleNamespace

import pytest
from openpyxl import Workbook

from sarex_loader import folder_ledger as ledger_module
from sarex_loader import production_folders as folders
from sarex_loader import production_scope, production_upload
from sarex_loader.api_client import ApiSettings, SarexClient
from sarex_loader.api_models import ApiError
from sarex_loader.api_transport import BearerToken
from sarex_loader.audit import HEADERS
from sarex_loader.cli import main
from sarex_loader.folder_ledger import FolderLedger, operation_key, validate_plan
from sarex_loader.folder_resolver import FolderResolver
from sarex_loader.folder_transport import FolderHTTPSTransport
from sarex_loader.read_only_policy import DOCUMENTATION_BASE
from sarex_loader.recovery_config import parse_recovery_config
from sarex_loader.recursive_gateway import PROFILE_ROOTS
from sarex_loader.safety import ValidationError
from sarex_loader.single_test_identity import INDEPENDENT_OPERATION_ID
from sarex_loader.single_test_scope import TEST_DISK_ID
from sarex_loader.synthetic_pdf import synthetic_pdf_bytes
from sarex_loader.tree_source import add_response
from sarex_loader.upload_preview import run_full_preview
from sarex_loader.user_settings import UserSettings, load_settings, save_settings
from tests.test_api_client import forbid_network as forbid_network
from tests.test_https_transport import https_mock as https_mock
from tests.test_https_transport import wire


@pytest.fixture(params=['sk', 'vk'])
def example(tmp_path, monkeypatch, request):
    profile = request.param
    source = tmp_path / 'исходники'
    source.mkdir()
    pdf = source / 'PDF'
    pdf.mkdir()
    excel = source / 'реестр.xlsx'
    book = Workbook()
    book.active.append(HEADERS)
    book.active.append([1, datetime(2026, 11, 5), 'Офис', 'Компания', '123', None])
    book.save(excel)
    book.close()
    filename = '2026-11-05-Синтетика-123.pdf'
    (pdf / filename).write_bytes(synthetic_pdf_bytes())
    root, root_name = PROFILE_ROOTS[profile]
    path = [1600045, 2062798, root, 500, 501, 502, 503]
    nodes = [{'id': i, 'name': name, 'is_folder': True, 'disk_id': TEST_DISK_ID,
              'path': '.'.join(map(str, path[:n + 3]))}
             for n, (i, name) in enumerate(zip(path[2:],
                 [root_name, 'Офис', 'Компания', 'Инспекции', '2026-10'], strict=True))]
    tree = FolderResolver()
    raw = json.dumps({'documents': nodes}).encode()
    for node in nodes:
        add_response(tree, raw, 1024**2, queried_folder=node['id'])
    tree.observation = {
        'version': 3, 'source': 'gateway', 'root_ids': [root],
        'traversal_status': 'COMPLETED_OBSERVED_TREE', 'root_verified': True,
        'unvisited_folder_ids': [], 'global_error': None, 'failed_folders': {},
        'context_names': {}, 'completeness_description': 'Mock',
        'queried_at': {str(i): '2026-11-05T12:00:00+00:00' for i in tree.queried_folders}}
    config = parse_recovery_config({
        'mode': 'tree-recovery', 'input_root': str(source), 'filename_separator': '-',
        'url_contract_confirmed': True,
        'tree': {'source': 'gateway', 'disk_id': TEST_DISK_ID,
                 'root_ids': [root], 'traversal': 'recursive'},
        'registries': [{'excel': excel.name, 'inspection_type': profile, 'root_id': str(root),
                        'office_folders': {'Офис': 'Офис'},
                        'contractor_folders': {'Компания': 'Компания'},
                        'inspection_folder': 'Инспекции',
                        'folder_routes': [{'office': 'Офис', 'contractor': 'Компания',
                            'components': ['{office}', '{contractor}', 'Инспекции', '{month}']}]}]})
    monkeypatch.setattr(production_scope, 'journal_path', lambda: tmp_path / 'upload-journal')
    monkeypatch.setattr(production_upload, 'journal_path', production_scope.journal_path)
    monkeypatch.setattr(ledger_module, 'journal_path', lambda: tmp_path / 'folder-journal')
    @contextmanager
    def login():
        yield lambda: BearerToken('SYNTHETIC-TOKEN')
    monkeypatch.setattr(folders, 'gateway_login', login)
    monkeypatch.setattr(production_upload, 'fresh_children', lambda *args: tree.children[502])
    def preview(name):
        return run_full_preview(config, {profile: [pdf]}, tmp_path / (name + '-preview'),
                                flat=True, plan_moves=True, tree_index=tree)
    def run(name, enabled=True, answer='да', mutate=None):
        report = preview(name)
        if mutate:
            mutate(report)
        return production_upload.run(config, tree, report, pdf, excel, tmp_path / name,
                                     UserSettings('synthetic', 'synthetic', enabled),
                                     ask=lambda _: answer)
    created = {'id': 900001, 'name': '2026-11', 'is_folder': True, 'disk_id': TEST_DISK_ID,
               'path': '.'.join(map(str, [*path[:-1], 900001]))}
    return SimpleNamespace(run=run, preview=preview, tree=tree, config=config, pdf=pdf,
                           excel=excel, nodes=nodes, created=created, root=root)


def posts(harness):
    return [bytes(s.sent) for s in harness.sockets if bytes(s.sent).startswith(b'POST ')]


def test_switch_is_local_and_preserves_credentials(tmp_path, monkeypatch, capsys):
    path = tmp_path / 'account.toml'
    monkeypatch.setenv('SAREX_ACCOUNT_FILE', str(path))
    assert main(['-folders', 'status']) == 0
    assert not path.exists()
    save_settings(UserSettings('fake-user', 'secret-example', results_dir=str(tmp_path)), path)
    for action, expected in [('on', True), ('status', True), ('off', False)]:
        assert main(['-folders', action]) == 0
        state = load_settings(path)
        assert state.allow_folder_creation is expected
        assert state.username == 'fake-user'
        assert state.password == 'secret-example'  # noqa: S105 — synthetic fixture
        assert state.results_dir == str(tmp_path)
    before = path.read_bytes()
    assert main(['-folders', 'maybe']) == 2
    assert path.read_bytes() == before
    assert 'secret-example' not in capsys.readouterr().out


def test_creation_get_verified_and_repeat_no_post(example, https_mock, monkeypatch):
    e = example
    original = e.excel.read_bytes()
    https_mock.responses = [wire(e.nodes[0]), wire(e.nodes[-2]),
                            wire(e.created), wire(e.created)]
    result = e.run('first')
    assert result['folders'][0]['status'] == 'CREATED', result['folders']
    assert result['uploaded'] == result['urls_written'] == 0
    assert len(posts(https_mock)) == 1
    payload = json.loads(posts(https_mock)[0].split(b'\r\n\r\n')[1])
    assert payload == {'disk_id': TEST_DISK_ID, 'parent_id': 502,
                       'name': '2026-11', 'is_folder': True}
    assert e.excel.read_bytes() == original
    fresh = FolderResolver()
    add_response(fresh, json.dumps({'documents': [*e.nodes, e.created]}).encode(), 1024**2)
    monkeypatch.setattr(production_upload, 'fresh_children', lambda *args: fresh.children[502])
    https_mock.responses = [wire(e.nodes[0]), wire(e.nodes[-2]), wire(e.created)]
    result = e.run('repeat')
    assert result['folders'][0]['status'] == 'ALREADY_EXISTS'
    assert len(posts(https_mock)) == 1


@pytest.mark.parametrize('enabled,answer,status', [(False, 'да', None), (True, 'нет', 'DECLINED')])
def test_default_off_and_decline_never_send(example, https_mock, enabled, answer, status):
    result = example.run('off', enabled=enabled, answer=answer)
    assert result['folders'] == [] if status is None else result['folders'][0]['status'] == status
    assert not https_mock.sockets


@pytest.mark.parametrize('reason', ['DATE_MISMATCH', 'DUPLICATE_SHA256', 'ROUTE_NOT_CONFIGURED',
                                  'REMOTE_DOCUMENT_EXISTS'])
def test_error_pdf_does_not_request_folder(example, https_mock, reason):
    result = example.run('bad', mutate=lambda r: r['files'][0]['reasons'].append(reason))
    assert not result['folders'] and not https_mock.sockets


def test_403_is_recorded_and_later_explicit_retry_possible(example, https_mock):
    e = example
    https_mock.responses = [wire(e.nodes[0]), wire(e.nodes[-2]), wire({}, status=403)]
    result = e.run('forbidden')
    assert result['folders'][0]['status'] == 'FORBIDDEN'
    assert not result['stopped']
    https_mock.responses = [wire(e.nodes[0]), wire(e.nodes[-2]),
                            wire(e.created), wire(e.created)]
    assert e.run('retry')['folders'][0]['status'] == 'CREATED'
    assert len(posts(https_mock)) == 2


@pytest.mark.parametrize('failure', ['invalid_response', 'verify_403', 'server_500', 'ancestor_id'])
def test_unknown_stops_and_is_not_bypassed_by_off(example, https_mock, failure):
    e = example
    https_mock.responses = [wire(e.nodes[0]), wire(e.nodes[-2])]
    if failure == 'invalid_response':
        https_mock.responses += [wire({**e.created, 'is_folder': False})]
    elif failure == 'verify_403':
        https_mock.responses += [wire(e.created), wire({}, status=403)]
    elif failure == 'ancestor_id':
        https_mock.responses += [wire(e.created | {
            'id': 502, 'path': e.created['path'].rsplit('.', 1)[0] + '.502'})]
    else:
        https_mock.responses += [wire({}, status=500)]
    result = e.run('unknown')
    assert result['stopped'] and result['folders'][0]['status'] == 'OUTCOME_UNKNOWN'
    with pytest.raises(ValidationError, match='OUTCOME_UNKNOWN'):
        e.run('retry', enabled=False)
    assert len(posts(https_mock)) == 1


def test_incomplete_tree_blocks_creation(example, https_mock):
    example.tree.observation['failed_folders'] = {'502': 'TIMEOUT'}
    with pytest.raises(ValidationError):
        example.run('incomplete')
    assert not https_mock.sockets


def test_get_preflight_failure_never_posts(example, https_mock):
    e = example
    https_mock.responses = [wire(e.nodes[0]), wire({**e.nodes[-2], 'path': '1.2.502'})]
    result = e.run('wrong-parent')
    assert result['folders'][0]['status'] == 'SKIPPED'
    assert not posts(https_mock)


def test_folder_ledger_crash_and_candidate_preserved(example):
    e = example
    report = e.preview('plan')
    report['files'][0]['reasons'].remove('PDF_CONTENT_NOT_VERIFIED')
    plan, = folders.prepare_plans(e.config, e.tree, report)
    with FolderLedger([e.pdf.parent]) as journal:
        key = journal.reserve(plan)
        journal.begin(key)
        journal.candidate(key, 900001)
    with pytest.raises(ValidationError, match='OUTCOME_UNKNOWN'):
        FolderLedger([e.pdf.parent])
    # Read-only snapshot through the base reader does not understand folder states;
    # inspect SQLite read-only for evidence without changing UNKNOWN.
    import sqlite3
    uri = (ledger_module.journal_path() / 'journal.sqlite').as_uri() + '?mode=ro'
    connection = sqlite3.connect(uri, uri=True)
    try:
        assert connection.execute('SELECT state,document_id FROM operations').fetchone() == (
            'OUTCOME_UNKNOWN', 900001)
    finally:
        connection.close()


@pytest.mark.parametrize('change', [ {'parent_id': 777}, {'root_id': 2093037},
                                    {'name': '../2026-11'}, {'name': 'Компания'},
                                    {'month': '2026-12'}])
def test_scope_rejected(example, change):
    report = example.preview('plan')
    report['files'][0]['reasons'].remove('PDF_CONTENT_NOT_VERIFIED')
    plan, = folders.prepare_plans(example.config, example.tree, report)
    with pytest.raises(ValidationError):
        validate_plan(plan | change)


def test_transport_rejects_wrong_name_and_other_resource(example, https_mock):
    report = example.preview('plan')
    report['files'][0]['reasons'].remove('PDF_CONTENT_NOT_VERIFIED')
    plan, = folders.prepare_plans(example.config, example.tree, report)
    with FolderLedger([example.pdf.parent]) as journal:
        key = journal.reserve(plan)
        assert key == operation_key(plan)
        transport = FolderHTTPSTransport(journal, key, plan, confirmed=True)
        client = SarexClient(ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',)),
                             token=BearerToken('SYNTHETIC'), transport=transport,
                             folder_network_enabled=True)
        journal.begin(key)
        with pytest.raises(ApiError):
            client.create_month_folder(disk_id=TEST_DISK_ID, parent_id=502, name='2026-12')
        with pytest.raises(ApiError):
            client.get_document(502)
        assert not https_mock.sockets


def test_empty_ledger_reopens_and_second_writer_blocked(example):
    protected = [example.pdf.parent]
    with FolderLedger(protected):
        with pytest.raises(ValidationError):
            FolderLedger(protected)
    with FolderLedger(protected) as journal:
        assert journal.checkpoints() == {}


def test_partial_success_continues_after_explicit_denial(example, https_mock):
    from openpyxl import load_workbook

    e = example
    book = load_workbook(e.excel)
    book.active.append([2, datetime(2026, 12, 5), 'Офис', 'Компания', '124', None])
    book.save(e.excel)
    book.close()
    (e.pdf / '2026-12-05-Синтетика-124.pdf').write_bytes(
        synthetic_pdf_bytes(INDEPENDENT_OPERATION_ID))
    december = e.created | {'id': 900002, 'name': '2026-12',
                           'path': e.created['path'].rsplit('.', 1)[0] + '.900002'}
    https_mock.responses = [wire(e.nodes[0]), wire(e.nodes[-2]), wire({}, status=403),
                            wire(e.nodes[0]), wire(e.nodes[-2]), wire(december), wire(december)]
    result = e.run('partial')
    assert [p['status'] for p in result['folders']] == ['FORBIDDEN', 'CREATED']
    assert result['uploaded'] == 0 and len(posts(https_mock)) == 2


def test_changed_gateway_children_skip_without_post(example, https_mock, monkeypatch):
    e = example
    https_mock.responses = [wire(e.nodes[0]), wire(e.nodes[-2])]
    def fail(*args):
        raise ValidationError('TREE_PAGINATION_UNSUPPORTED')
    monkeypatch.setattr(production_upload, 'fresh_children', fail)
    assert e.run('pagination')['folders'][0]['status'] == 'SKIPPED'
    assert not posts(https_mock)


@pytest.mark.parametrize('command', ['preview', 'fill'])
def test_profile_read_modes_ignore_enabled_creation(example, tmp_path, monkeypatch, command):
    from contextlib import nullcontext

    from sarex_loader import profile_workflow

    e = example
    e.tree.refresh_metrics = {'get_attempts': 5, 'pdf_documents': 0, 'get_retries': 0,
                              'folders_unchecked': 0}
    monkeypatch.setattr(profile_workflow, 'profile_config', lambda *args: e.config)
    monkeypatch.setattr(profile_workflow, 'read_tree', lambda *args, **kwargs: e.tree)
    monkeypatch.setattr(profile_workflow, 'GatewayCheckpoint',
                        lambda *args, **kwargs: nullcontext())
    def never(*args, **kwargs):
        pytest.fail('Read-only profile invoked folder creation')
    monkeypatch.setattr(folders, 'finish', never)
    original = e.excel.read_bytes()
    result = profile_workflow.run_profile(
        command, e.config.registries[0].inspection_type, e.excel,
        f'https://lk.sarex.io/documentations/{e.root}', tmp_path / 'reports',
        UserSettings('fake', 'fake', True), pdf=e.pdf if command == 'preview' else None)
    assert result
    assert not ledger_module.journal_path().exists()
    assert e.excel.read_bytes() == original  # No remote PDF exists, so fill leaves cells untouched.


def test_existing_pdf_upload_precedes_month_creation(example, https_mock, monkeypatch):
    from openpyxl import load_workbook

    e = example
    existing_name = '2026-10-05-Синтетика-124.pdf'
    book = load_workbook(e.excel)
    book.active.append([2, datetime(2026, 10, 5), 'Офис', 'Компания', '124', None])
    book.save(e.excel)
    book.close()
    (e.pdf / existing_name).write_bytes(synthetic_pdf_bytes(INDEPENDENT_OPERATION_ID))
    existing = {'id': 900003, 'name': existing_name, 'is_folder': False,
                'disk_id': TEST_DISK_ID, 'path': e.nodes[-1]['path'] + '.900003',
                'bundles': None, 'type': 'pdf'}
    monkeypatch.setattr(production_upload, 'gateway_login', folders.gateway_login)
    monkeypatch.setattr(production_upload, 'fresh_children',
                        lambda config, index, parent, provider: e.tree.children.get(parent, {}))
    https_mock.responses = [wire(e.nodes[-1]), wire(e.nodes[0]),
        wire({'types': [{'name': 'pdf', 'fields': [{'key': 'pdf', 'file': True,
                                                 'can_be_uploaded_by_user': True}]}]}),
        wire({'id': 'synthetic-bundle', 'document_id': None, 'upload_status': 'created'}),
        wire(body=b''), wire({'id': 'synthetic-bundle', 'upload_status': 'uploaded'}),
        wire(existing), wire(existing), wire(e.nodes[0]), wire(e.nodes[-2]),
        wire(e.created), wire(e.created)]
    result = e.run('mixed')
    assert result['uploaded'] == result['urls_written'] == 1
    assert result['folders'][0]['status'] == 'CREATED'
    sent = posts(https_mock)
    assert len(sent) == 5
    assert json.loads(sent[-1].split(b'\r\n\r\n')[1])['is_folder'] is True
