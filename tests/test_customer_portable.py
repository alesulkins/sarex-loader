"""Native file handling + real customer 99-Test orchestration, fake HTTPS only."""
import json
from contextlib import contextmanager

from sarex_loader import customer_test as flow
from sarex_loader import customer_test_scope as scope
from sarex_loader.api_transport import BearerToken
from sarex_loader.folder_resolver import FolderResolver
from sarex_loader.tree_source import add_response
from sarex_loader.user_settings import UserSettings
from tests.test_api_client import forbid_network as forbid_network
from tests.test_https_transport import https_mock as https_mock
from tests.test_https_transport import wire


def test_customer_prepare_send_get_excel_and_repeat(tmp_path, monkeypatch, https_mock):
    monkeypatch.setattr(scope, 'state_path', lambda: tmp_path / 'тестовый PDF')
    path = scope.TEST_PATH_IDS
    names = ('root', 'project', '99-Тест', '2026-10-Тест ПО (Автоматизация)',
             'ТЕСТ ЗАГРУЗКИ', '1-ОФ', 'РТ-Инжиниринг', 'Инспекции', '2026-10')
    nodes = [{'id': i, 'name': name, 'path': '.'.join(map(str, path[:n+1])), 'is_folder': True}
             for n, (i, name) in enumerate(zip(path, names, strict=True))]
    tree = FolderResolver()
    add_response(tree, json.dumps({'documents': nodes}).encode(), 1024**2)
    monkeypatch.setattr(flow, 'read_targets', lambda _: (tree, {}))
    monkeypatch.setattr(flow, 'require_settings', lambda: UserSettings('fake', 'fake'))
    @contextmanager
    def login():
        yield lambda: BearerToken('SYNTHETIC-TOKEN')
    monkeypatch.setattr(flow, 'gateway_login', login)
    preview = flow.run()
    assert preview['dry_run'] and not https_mock.sockets
    doc = {'id': 9000002, 'name': preview['filename'], 'is_folder': False, 'type': 'pdf',
           'path': '.'.join(map(str, (*path, 9000002))), 'bundles': None,
           'disk_id': scope.TEST_DISK_ID}
    prefix = [wire(nodes[-1]), wire(nodes[2])]
    https_mock.responses = [*prefix, wire({'types': [{'name': 'pdf', 'fields': [
        {'key': 'pdf', 'file': True, 'can_be_uploaded_by_user': True}]}]}),
        wire({'id': 'test-bundle', 'document_id': None, 'upload_status': 'created'}),
        wire(body=b''), wire({'id': 'test-bundle', 'upload_status': 'uploaded'}),
        wire(doc), wire(doc)]
    result = flow.run(expected_plan=preview['plan_sha256'], ask=lambda _: 'да')
    assert result['uploaded'] == 1 and not result['errors']
    before = sum(bytes(s.sent).startswith(b'POST ') for s in https_mock.sockets)
    assert before == 4
    https_mock.responses = [*prefix, wire(doc)]
    repeated = flow.run(expected_plan=preview['plan_sha256'], ask=lambda _: 'да')
    assert repeated['already_confirmed'] == 1 and repeated['uploaded'] == 0
    assert sum(bytes(s.sent).startswith(b'POST ') for s in https_mock.sockets) == before
