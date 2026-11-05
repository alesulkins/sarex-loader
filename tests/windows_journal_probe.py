"""Run with native Python on Windows or macOS; synthetic files, no network, no Sarex.

    python tests/windows_journal_probe.py > windows-journal-result.json

Requires the project to be installed. All SQLite files are created in a new temp directory.
"""
import hashlib
import json
import os
import platform
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import closing
from pathlib import Path

from sarex_loader.journal import Journal, fingerprint
from sarex_loader.safety import ValidationError

ITEM = {'status': 'LOCAL_MATCH', 'number': 'WINDOWS-PROBE-SYNTHETIC'}
KEY = fingerprint(ITEM)


def no_network(event, args):
    if event.startswith(('socket.connect', 'socket.bind', 'urllib.')):
        raise RuntimeError('Проверка не разрешает сетевые запросы')


def child(root, mode):
    source, path = root / 'входные данные', root / 'SQLite журнал'
    if mode == 'lock':
        try:
            with Journal(path, [source]):
                return 1
        except (ValidationError, OSError):
            return 0
    with Journal(path, [source]) as journal:
        journal.register({'synthetic': True}, {KEY: ITEM})
        journal.begin_request(KEY, 'CREATE_BUNDLE')
        journal.record_response_candidates(KEY, 'CREATE_BUNDLE', {'id': 'candidate-only'})
        os._exit(23)  # Only this disposable child; preserve a committed uncertain intent.


def run_child(root, mode):
    return subprocess.run(  # noqa: S603
        [sys.executable, str(Path(__file__).resolve()), '--child', str(root), mode],
        capture_output=True, timeout=30, check=False)


def file_hashes(path):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in path.iterdir()}


def require(value):
    if not value:
        raise RuntimeError('Проверка журнала не пройдена')


def run_probe():
    with tempfile.TemporaryDirectory(prefix='sarex-sqlite-') as temp:
        root = Path(temp).resolve()
        source, path = root / 'входные данные', root / 'SQLite журнал'
        source.mkdir()
        with Journal(path, [source]) as journal:
            journal.register({'synthetic': True}, {KEY: ITEM})
            require(journal._db.execute('PRAGMA busy_timeout').fetchone() == (5000,))
            require(journal._db.execute('PRAGMA synchronous').fetchone() == (2,))
            require(journal._db.execute('PRAGMA journal_mode').fetchone() == ('persist',))
            require(run_child(root, 'lock').returncode == 0)
        require(run_child(root, 'crash').returncode == 23)
        with Journal(path, [source]) as journal:
            require(journal.checkpoint(KEY)['state'] == 'OUTCOME_UNKNOWN')
            require(journal.checkpoint(KEY)['bundle_id'] is None)
            require(journal.response_candidates(KEY)[0]['bundle_id'] == 'candidate-only')
            try:
                journal.begin_request(KEY, 'CREATE_BUNDLE')
            except ValidationError:
                pass
            else:
                raise RuntimeError('Неопределённая операция ошибочно разрешена')
        before = file_hashes(path)
        require(Journal.peek(path)[2][KEY]['state'] == 'OUTCOME_UNKNOWN')
        require(file_hashes(path) == before)
        # A DIFFERENT synthetic operation/plan, not a bypass of the unknown operation.
        ready = threading.Event()
        reader_errors = []
        successful_path = root / 'другая синтетическая операция'
        def reader():
            try:
                with closing(sqlite3.connect(
                        (successful_path / 'journal.sqlite').as_uri() + '?mode=ro',
                        uri=True)) as db:
                    db.execute('BEGIN')
                    db.execute('SELECT * FROM operations').fetchall()
                    ready.set()
                    time.sleep(0.25)
                    db.rollback()
            except BaseException as exc:
                reader_errors.append(type(exc).__name__)
                ready.set()
        item = {'status': 'LOCAL_MATCH', 'number': 'OTHER-SYNTHETIC-OPERATION'}
        key = fingerprint(item)
        with Journal(successful_path, [source]) as journal:
            journal.register({'other-synthetic': True}, {key: item})
            thread = threading.Thread(target=reader)
            thread.start()
            require(ready.wait(5))
            try:
                for phase, result in [('CREATE_BUNDLE', {'bundle_id': 'synthetic'}),
                                      ('UPLOAD_SINGLE', {}), ('UPLOAD_FINISH', {}),
                                      ('CREATE_DOCUMENT', {'document_id': 42})]:
                    journal.run_mock_step(key, phase, lambda result=result: result)
                journal.mark_mock_url_checked(key, 42)
            finally:
                thread.join(10)
            require(not thread.is_alive() and not reader_errors)
        with Journal(successful_path, [source]) as journal:
            journal.register({'other-synthetic': True}, {key: item})
            require(journal.checkpoint(key)['state'] == 'ATTACHED')
            replay_calls = []
            try:
                journal.run_mock_step(key, 'CREATE_BUNDLE', lambda: replay_calls.append(1))
            except ValidationError:
                pass
            else:
                raise RuntimeError('Повтор ошибочно разрешён')
            require(not replay_calls)
        return {
            'platform': platform.system(), 'python': platform.python_version(),
            'sqlite': sqlite3.sqlite_version,
            'checks': {'one_writer': True, 'unicode_paths': True, 'crash_resume_unknown': True,
                       'candidate_preserved': True, 'unknown_retry_blocked': True,
                       'read_only_peek_unchanged': True, 'concurrent_reader': True,
                       'confirmed_state_after_reopen': 'ATTACHED', 'replay_effects': 0},
            'sarex_requests': 0, 'historical_databases_opened': 0,
        }


if __name__ == '__main__':
    sys.addaudithook(no_network)
    if len(sys.argv) == 4 and sys.argv[1] == '--child':
        sys.exit(child(Path(sys.argv[2]), sys.argv[3]))
    print(json.dumps(run_probe(), ensure_ascii=False, indent=2))
