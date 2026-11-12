"""Private SQLite checkpoints for POSIX and Windows; no network authorization."""

import hashlib
import json
import os
import re
import sqlite3
import stat
from contextlib import ExitStack, contextmanager
from pathlib import Path

from sarex_loader.config import local_path
from sarex_loader.file_safety import directory_fd
from sarex_loader.process_lock import lock_file
from sarex_loader.response_candidates import CANDIDATE_PHASES, response_candidates, safe_bundle_id
from sarex_loader.safety import ValidationError

MAX_DB_BYTES = 256 * 1024**2
# A short external read must not turn a successful effect into an uncertain one.
# This waits for SQLite locks only; it NEVER retries an API request or transaction.
BUSY_TIMEOUT_MS = 5000
SCHEMA = {
    'meta': 'CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
    'operations': '''CREATE TABLE operations (
        key TEXT PRIMARY KEY, payload TEXT NOT NULL, state TEXT NOT NULL,
        phase TEXT, bundle_id TEXT, document_id INTEGER, url_status TEXT NOT NULL)''',
}
CANDIDATE_SCHEMA = '''CREATE TABLE response_candidates (
        operation_key TEXT NOT NULL, phase TEXT NOT NULL,
        bundle_id TEXT, document_id INTEGER,
        PRIMARY KEY (operation_key, phase))'''
TRANSITIONS = {
    'CREATE_BUNDLE': ('PLANNED', 'BUNDLE_CREATED'),
    'UPLOAD_SINGLE': ('BUNDLE_CREATED', 'FILE_SENT'),
    'UPLOAD_FINISH': ('FILE_SENT', 'FINISHED'),
    'CREATE_DOCUMENT': ('FINISHED', 'ATTACHED'),
    'ADD_BUNDLE': ('FINISHED', 'ATTACHED'),
}
STATES = {'PLANNED', 'BLOCKED', 'IN_FLIGHT', 'OUTCOME_UNKNOWN', 'BUNDLE_CREATED',
          'FILE_SENT', 'FINISHED', 'ATTACHED', 'DOCUMENT_CREATED', 'DOCUMENT_VERIFIED'}
BATCH_DOCUMENT_STATES = {'DOCUMENT_CREATED', 'DOCUMENT_VERIFIED'}
BATCH_CONFIRMATION_POLICY = 'create-response-and-get-v1'


def batch_document_policy(payload):
    return (payload.get('mode') in {'batch-test-v2', 'production-upload-v1'}
            and payload.get('confirmation_policy') == BATCH_CONFIRMATION_POLICY)


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                      allow_nan=False)


def fingerprint(value: object) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _windows_platform():
    return os.name == 'nt'


class Journal:
    """One private directory/plan, one advisory process lock, FULL durable commits.

    A replaced/copied journal cannot establish remote exactly-once semantics. This is
    not a sandbox against malicious code running as the same OS user.
    """

    def __init__(self, path: Path, input_roots: list[Path]):
        self._stack = ExitStack()
        self._storage = None
        self._db = None
        self._failed = False
        self.path = local_path(path).absolute()
        input_roots = [local_path(root).absolute() for root in input_roots]
        if not input_roots or any(self.path.is_relative_to(root) or root.is_relative_to(self.path)
                                  for root in input_roots):
            raise ValidationError('Журнал должен быть отдельно от входных каталогов.')
        try:
            new = self._prepare_storage()
            uri = (self.path / 'journal.sqlite').as_uri() + '?mode=rw'
            self._db = sqlite3.connect(uri, uri=True, timeout=BUSY_TIMEOUT_MS / 1000,
                                       isolation_level=None)
            self._stack.callback(self._db.close)
            self._verify_directory()
            self._db.execute('PRAGMA trusted_schema=OFF')
            self._db.execute('PRAGMA temp_store=MEMORY')
            self._db.execute('PRAGMA cache_size=-8192')
            self._db.execute('PRAGMA mmap_size=0')
            self._db.execute(f'PRAGMA busy_timeout={BUSY_TIMEOUT_MS}')
            self._db.execute('PRAGMA synchronous=FULL')
            self._db.execute('PRAGMA fullfsync=ON')
            if new:
                self._db.execute('PRAGMA page_size=4096')
                self._db.execute('PRAGMA journal_mode=PERSIST')
                self._db.execute('PRAGMA max_page_count=65536')
                with self._transaction():
                    for statement in SCHEMA.values():
                        self._db.execute(statement)
                    self._db.execute("INSERT INTO meta VALUES ('schema', '1')")
                self._sync_directory()
            else:
                self._validate_database()
                self._db.execute('PRAGMA journal_mode=PERSIST')
                self._db.execute('PRAGMA max_page_count=65536')
            if self._db.execute(
                    "SELECT 1 FROM operations WHERE state='IN_FLIGHT' LIMIT 1").fetchone():
                with self._transaction():
                    self._db.execute("UPDATE operations SET state='OUTCOME_UNKNOWN' "
                                     "WHERE state='IN_FLIGHT'")
        except Exception:
            self._stack.close()
            raise ValidationError('Журнал недоступен, повреждён, небезопасен или занят.') from None
        except BaseException:
            self._stack.close()
            raise

    def _prepare_storage(self):
        if _windows_platform():
            from sarex_loader.windows_journal import WindowsJournalStorage

            self._storage = WindowsJournalStorage(self.path, self._stack, MAX_DB_BYTES)
            return self._storage.new
        parent = self._stack.enter_context(directory_fd(self.path.parent))
        # Private leaf permissions alone do not prevent another user from renaming
        # it through a writable ancestor. Root-owned sticky /tmp is a safe exception.
        for ancestor in (*reversed(self.path.parent.parents), self.path.parent):
            info = ancestor.lstat()
            if (info.st_uid not in {0, os.getuid()}
                    or info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                raise ValidationError('Нужны защищённые родительские каталоги журнала.')
        try:
            os.mkdir(self.path.name, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
        self._directory = self._stack.enter_context(directory_fd(self.path))
        info = os.fstat(self._directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValidationError('Нужен собственный приватный каталог журнала с правами 0700.')
        self._directory_identity = (info.st_dev, info.st_ino)
        self._check_files()
        lock = self._open_private('process.lock')
        self._stack.callback(os.close, lock)
        lock_file(lock)
        self._check_files()
        new = not (self.path / 'journal.sqlite').exists()
        db_fd = self._open_private('journal.sqlite')
        self._stack.callback(os.close, db_fd)
        self._db_identity = os.fstat(db_fd).st_ino
        self._verify_directory()
        return new

    def _sync_directory(self):
        if self._storage is not None:
            self._storage.sync()
        else:
            os.fsync(self._directory)

    def _open_private(self, name: str) -> int:
        try:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self._directory)
            try:
                self._sync_directory()
            except BaseException:
                os.close(fd)
                raise
        except FileExistsError:
            fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._directory)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
            os.close(fd)
            raise ValidationError('Небезопасный файл журнала.')
        return fd

    def _check_files(self) -> None:
        if self._storage is not None:
            return self._storage.check_files()
        allowed = {'process.lock', 'journal.sqlite', 'journal.sqlite-journal'}
        with os.scandir(self._directory) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                if (entry.name not in allowed or not stat.S_ISREG(info.st_mode)
                        or info.st_nlink != 1 or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_DB_BYTES):
                    raise ValidationError('Неожиданный или небезопасный файл в каталоге журнала.')

    def _verify_directory(self) -> None:
        if self._storage is not None:
            return self._storage.verify()
        with directory_fd(self.path) as fd:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != self._directory_identity:
                raise ValidationError('Каталог журнала изменился.')
        self._check_files()
        info = os.stat('journal.sqlite', dir_fd=self._directory, follow_symlinks=False)
        if info.st_ino != self._db_identity:
            raise ValidationError('Файл журнала заменён.')

    def _validate_database(self) -> None:
        found = dict(self._db.execute(
            "SELECT name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"))
        version = self._db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
        expected = (SCHEMA if version == ('1',) else
                    {**SCHEMA, 'response_candidates': CANDIDATE_SCHEMA})
        if found != expected or self._db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise ValidationError('Схема или целостность журнала нарушена.')
        if version not in {('1',), ('2',)}:
            raise ValidationError('Неизвестная версия журнала.')
        if self._db.execute('PRAGMA page_size').fetchone() != (4096,):
            raise ValidationError('Неизвестный размер страниц журнала.')
        if (self._db.execute('SELECT count(*) FROM operations').fetchone()[0] > 150_000
                or self._db.execute('SELECT count(*) FROM meta').fetchone()[0] > 2):
            raise ValidationError('Журнал превышает лимиты записей.')
        for key, state, phase, bundle, document, url in self._db.execute(
            'SELECT key,state,phase,bundle_id,document_id,url_status FROM operations'
        ):
            if (state not in STATES or phase is not None and phase not in TRANSITIONS
                    or state in {'PLANNED', 'BLOCKED'} and phase is not None
                    or state not in {'PLANNED', 'BLOCKED'} and phase is None
                    or state in {'BUNDLE_CREATED', 'FILE_SENT', 'FINISHED', 'ATTACHED'}
                    and TRANSITIONS[phase][1] != state
                    or state in {'BUNDLE_CREATED', 'FILE_SENT', 'FINISHED', 'ATTACHED'}
                    and (not isinstance(bundle, str)
                         or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', bundle))
                    or state in BATCH_DOCUMENT_STATES and (
                        phase != 'CREATE_DOCUMENT' or not safe_bundle_id(bundle)
                        or not batch_document_policy(self.operation(key)))
                    or state in {'ATTACHED', *BATCH_DOCUMENT_STATES}
                    and (type(document) is not int or not 0 < document < 2**63)
                    or url not in {'UNVERIFIED', 'MOCK_CHECKED', 'DOCUMENT_CHECKED'}
                    or url == 'MOCK_CHECKED' and state != 'ATTACHED'
                    or url == 'DOCUMENT_CHECKED' and state not in {
                        'ATTACHED', 'OUTCOME_UNKNOWN', 'DOCUMENT_VERIFIED'}
                    or state == 'DOCUMENT_VERIFIED' and url != 'DOCUMENT_CHECKED'
                    or state == 'DOCUMENT_CREATED' and url != 'UNVERIFIED'):
                raise ValidationError('Некорректное состояние журнала.')
            if state in BATCH_DOCUMENT_STATES and (
                    version != ('2',) or not any(
                        c['phase'] == 'CREATE_DOCUMENT' and c['document_id'] == document
                        for c in self.response_candidates(key))):
                raise ValidationError('Нет сохранённого ответа создания документа.')
        if version == ('2',):
            if self._db.execute('SELECT count(*) FROM response_candidates').fetchone()[0] > 450_000:
                raise ValidationError('Слишком много идентификаторов для сверки.')
            for phase, bundle, document, state in self._db.execute(
                'SELECT c.phase,c.bundle_id,c.document_id,o.state FROM response_candidates c '
                'LEFT JOIN operations o ON o.key=c.operation_key'
            ):
                if (phase not in CANDIDATE_PHASES or state in {None, 'PLANNED', 'BLOCKED'}
                        or bundle is None and document is None
                        or bundle is not None and not safe_bundle_id(bundle)
                        or document is not None and (type(document) is not int
                                                     or not 0 < document < 2**63)
                        or phase == 'CREATE_DOCUMENT' and bundle is not None):
                    raise ValidationError('Некорректные идентификаторы для сверки.')
        for key, phase in self._db.execute(
                "SELECT key,phase FROM operations WHERE state='OUTCOME_UNKNOWN' "
                "AND url_status='DOCUMENT_CHECKED'"):
            if (phase != 'CREATE_DOCUMENT' or version != ('2',)
                    or not any(c['phase'] == 'CREATE_DOCUMENT' and c['document_id'] is not None
                               for c in self.response_candidates(key))):
                raise ValidationError('URL без candidate созданного документа.')

    def _check_writable(self):
        if self._failed:
            raise ValidationError('После ошибки журнала продолжение запрещено.')
        self._verify_directory()

    @contextmanager
    def _transaction(self):
        try:
            self._check_writable()
            self._db.execute('BEGIN IMMEDIATE')
            yield
            self._db.execute('COMMIT')
            self._sync_directory()
        except BaseException:
            self._failed = True
            if self._db.in_transaction:
                self._db.execute('ROLLBACK')
            raise

    def register(self, context: dict, operations: dict[str, dict]) -> dict[str, dict]:
        """Atomic whole-plan reservation. Reuse requires exact inputs/rules/metadata."""
        if len(operations) > 150_000:
            raise ValidationError('Превышен лимит операций журнала.')
        context_hash = fingerprint(context)
        encoded = {key: canonical(value) for key, value in operations.items()}
        if any(len(value) > 32768 for value in encoded.values()):
            raise ValidationError('Метаданные операции превышают лимит.')
        previous = self._db.execute("SELECT value FROM meta WHERE key='context'").fetchone()
        if previous is not None:
            stored = dict(self._db.execute('SELECT key,payload FROM operations'))
            if previous != (context_hash,) or stored != encoded:
                raise ValidationError('INPUTS_OR_RULES_CHANGED: нужен новый аудит и ручная сверка.')
        else:
            with self._transaction():
                self._db.execute("INSERT INTO meta VALUES ('context', ?)", (context_hash,))
                self._db.executemany(
                    'INSERT INTO operations VALUES (?,?,?,NULL,NULL,NULL,?)',
                    ((key, value, 'PLANNED' if operations[key]['status'] == 'LOCAL_MATCH'
                      else 'BLOCKED', 'UNVERIFIED') for key, value in encoded.items()))
        return self.checkpoints()

    def checkpoints(self) -> dict[str, dict]:
        return {key: {'state': state, 'phase': phase, 'bundle_id': bundle,
                      'document_id': document, 'url_status': url}
                for key, state, phase, bundle, document, url in self._db.execute(
                    'SELECT key,state,phase,bundle_id,document_id,url_status FROM operations')}

    def register_production(self, operations):
        """Append immutable intents ONLY to the new permanent production ledger.

        Old single-test/batch contexts cannot enter this API. No UPDATE/DELETE of
        existing intents, no changed key to bypass an uncertain inspection.
        """
        from sarex_loader.production_scope import (
            CONTEXT,
            journal_path,
            operation_key,
            stored_identity_keys,
            validate_item,
        )

        if self.path != journal_path():
            raise ValidationError('Нужен постоянный рабочий журнал загрузки.')
        previous = self._db.execute("SELECT value FROM meta WHERE key='context'").fetchone()
        if previous not in (None, (fingerprint(CONTEXT),)):
            raise ValidationError('Исторический журнал нельзя использовать как рабочий.')
        if any(c['state'] not in {'PLANNED', 'ATTACHED', *BATCH_DOCUMENT_STATES}
               for c in self.checkpoints().values()):
            raise ValidationError('OUTCOME_UNKNOWN_OR_INCOMPLETE: нужна сверка журнала; '
                                  'POST запрещён.')
        additions = []
        stored_operations = {key: json.loads(payload) for key, payload in self._db.execute(
            'SELECT key,payload FROM operations')}
        identities = stored_identity_keys(stored_operations)
        for key, item in operations.items():
            validate_item(item)
            identity = operation_key(item)
            if key != identities.get(identity, identity):
                raise ValidationError('Неверный постоянный ключ инспекции.')
            encoded = canonical(item)
            if len(encoded) > 32768:
                raise ValidationError('Метаданные операции превышают лимит.')
            stored = self._db.execute(
                'SELECT payload FROM operations WHERE key=?', (key,)).fetchone()
            if stored is not None and stored != (encoded,):
                raise ValidationError('Инспекция уже зарегистрирована с другим PDF '
                                      'или назначением.')
            if stored is None:
                additions.append((key, encoded, 'PLANNED', 'UNVERIFIED'))
            identities[identity] = key
        if previous is None or additions:
            with self._transaction():
                if previous is None:
                    self._db.execute("INSERT INTO meta VALUES ('context', ?)",
                                     (fingerprint(CONTEXT),))
                self._db.executemany('INSERT INTO operations VALUES (?,?,?,NULL,NULL,NULL,?)',
                                     additions)
        return self.checkpoints()

    def operation(self, key: str) -> dict:
        row = self._db.execute('SELECT payload FROM operations WHERE key=?', (key,)).fetchone()
        if row is None:
            raise ValidationError('Операция отсутствует в журнале.')
        return json.loads(row[0])

    @classmethod
    def peek(cls, path: Path):
        """Locked RAM snapshot for preview; no SQLite recovery/writes on the source."""
        from sarex_loader.file_safety import read_snapshot

        if _windows_platform():
            from sarex_loader.windows_journal import WindowsJournalStorage

            with ExitStack() as stack:
                storage = WindowsJournalStorage(local_path(path).absolute(), stack,
                                                MAX_DB_BYTES, read_only=True)
                return cls._peek_snapshot(storage.snapshot)

        with directory_fd(path) as fd:
            if (stat.S_IMODE(os.fstat(fd).st_mode) != 0o700
                    or os.fstat(fd).st_uid != os.getuid()):
                raise ValidationError('Небезопасный каталог журнала.')
            lock = os.open('process.lock', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                lock_file(lock, shared=True)
                obj = cls.__new__(cls)
                obj._storage = None
                obj._directory = fd
                obj._check_files()
                return cls._peek_snapshot(lambda name: read_snapshot(path / name, MAX_DB_BYTES)
                                          if (path / name).exists() else b'')
            finally:
                os.close(lock)

    @classmethod
    def _peek_snapshot(cls, read):
        try:
            raw = read('journal.sqlite-journal')
        except FileNotFoundError:
            raw = b''
        if raw and (len(raw) < 28 or raw[:28] != b'\0' * 28):
            raise ValidationError('JOURNAL_RECOVERY_REQUIRED')
        obj = cls.__new__(cls)
        obj._db = sqlite3.connect(':memory:')
        try:
            obj._db.deserialize(read('journal.sqlite'))
            obj._db.execute('PRAGMA trusted_schema=OFF')
            obj._db.execute('PRAGMA query_only=ON')
            obj._validate_database()
            context = obj._db.execute("SELECT value FROM meta WHERE key='context'").fetchone()
            operations = {k: json.loads(v) for k, v in obj._db.execute(
                'SELECT key,payload FROM operations')}
            return (context[0] if context else None), operations, obj.checkpoints()
        finally:
            obj._db.close()

    def mark_document_url_checked(self, key: str, document_id: int) -> None:
        """GET identity evidence only; never promote UNKNOWN or imply a Bundle link."""
        checkpoint = self.checkpoint(key)
        known = checkpoint['document_id']
        if checkpoint['state'] == 'OUTCOME_UNKNOWN':
            if checkpoint['phase'] != 'CREATE_DOCUMENT':
                raise ValidationError('Нет candidate созданного документа.')
            candidates = [c['document_id'] for c in self.response_candidates(key)
                          if c['phase'] == 'CREATE_DOCUMENT']
            known = candidates[0] if len(candidates) == 1 else None
        if (type(document_id) is not int or not 0 < document_id < 2**63
                or document_id != known
                or checkpoint['state'] not in {'ATTACHED', 'OUTCOME_UNKNOWN'}):
            raise ValidationError('Нет идентификатора для отдельной GET-проверки URL.')
        if checkpoint['url_status'] == 'DOCUMENT_CHECKED':
            self._check_writable()
            return
        with self._transaction():
            self._db.execute("UPDATE operations SET url_status='DOCUMENT_CHECKED' WHERE key=?",
                             (key,))

    def confirm_batch_document_get(self, key, document_id, *, bundle_link_confirmed):
        """Confirm a new batch GET; no transition from UNKNOWN, even with a matching candidate."""
        checkpoint = self.checkpoint(key)
        if (type(bundle_link_confirmed) is not bool or type(document_id) is not int
                or not batch_document_policy(self.operation(key))
                or checkpoint['state'] not in {'ATTACHED', *BATCH_DOCUMENT_STATES}
                or checkpoint['document_id'] != document_id):
            raise ValidationError('BATCH_CONFIRMED_CREATE_REQUIRED')
        state = ('ATTACHED' if bundle_link_confirmed or checkpoint['state'] == 'ATTACHED'
                 else 'DOCUMENT_VERIFIED')
        if checkpoint['state'] == state and checkpoint['url_status'] == 'DOCUMENT_CHECKED':
            self._check_writable()
            return
        with self._transaction():
            self._db.execute("UPDATE operations SET state=?,url_status='DOCUMENT_CHECKED' "
                             "WHERE key=?", (state, key))

    def checkpoint(self, key: str) -> dict:
        """Indexed single-operation read; avoid scanning all rows at each upload step."""
        row = self._db.execute(
            'SELECT state,phase,bundle_id,document_id,url_status FROM operations WHERE key=?',
            (key,)).fetchone()
        if row is None:
            raise ValidationError('Операция отсутствует в журнале.')
        return dict(zip(('state', 'phase', 'bundle_id', 'document_id', 'url_status'), row,
                        strict=True))

    def begin_request(self, key: str, phase: str) -> None:
        """Commit intent BEFORE an effect. This grants no network authorization."""
        if phase not in TRANSITIONS:
            raise ValidationError('Неизвестная фаза запроса.')
        expected, _ = TRANSITIONS[phase]
        with self._transaction():
            cursor = self._db.execute(
                "UPDATE operations SET state='IN_FLIGHT',phase=? WHERE key=? AND state=?",
                (phase, key, expected))
            if cursor.rowcount != 1:
                raise ValidationError('OUTCOME_UNKNOWN_OR_BLOCKED: повтор операции запрещён.')

    def record_response_candidates(self, key: str, phase: str, value: object) -> None:
        """Commit evidence BEFORE model validation; never advance state or confirmed IDs.

        Version 1 is extended only while recording an actual IN_FLIGHT response.
        Opening a historical journal does not migrate it. No raw response is stored.
        """
        bundle, document = response_candidates(phase, value)
        if bundle is None and document is None:
            return
        with self._transaction():
            row = self._db.execute('SELECT state,phase FROM operations WHERE key=?',
                                   (key,)).fetchone()
            if row != ('IN_FLIGHT', phase):
                raise ValidationError('Нет сохранённого намерения для идентификаторов ответа.')
            if self._db.execute("SELECT value FROM meta WHERE key='schema'").fetchone() == ('1',):
                self._db.execute(CANDIDATE_SCHEMA)
                self._db.execute("UPDATE meta SET value='2' WHERE key='schema'")
            previous = self._db.execute(
                'SELECT bundle_id,document_id FROM response_candidates '
                'WHERE operation_key=? AND phase=?', (key, phase)).fetchone()
            if previous is not None:
                if previous != (bundle, document):
                    raise ValidationError('Конфликт идентификаторов ответа; перезапись запрещена.')
                return
            self._db.execute('INSERT INTO response_candidates VALUES (?,?,?,?)',
                             (key, phase, bundle, document))

    def response_candidates(self, key: str) -> tuple[dict, ...]:
        """Unconfirmed evidence, separate from checkpoints and never used to choose a request."""
        if self._db.execute("SELECT value FROM meta WHERE key='schema'").fetchone() == ('1',):
            return ()
        return tuple({'phase': phase, 'bundle_id': bundle, 'document_id': document}
                     for phase, bundle, document in self._db.execute(
                         'SELECT phase,bundle_id,document_id FROM response_candidates '
                         'WHERE operation_key=? ORDER BY phase', (key,)))

    def confirm_request(self, key: str, *, bundle_id: str | None = None,
                        document_id: int | None = None, document_created_only=False) -> None:
        with self._transaction():
            row = self._db.execute('SELECT state,phase,bundle_id,document_id FROM operations '
                                   'WHERE key=?', (key,)).fetchone()
            if row is None or row[0] != 'IN_FLIGHT':
                raise ValidationError('Нет сохранённого намерения запроса.')
            _, phase, old_bundle, old_document = row
            if (type(document_created_only) is not bool or document_created_only and (
                    phase != 'CREATE_DOCUMENT' or not batch_document_policy(self.operation(key))
                    or not any(c['phase'] == phase and c['document_id'] == document_id
                               for c in self.response_candidates(key)))):
                raise ValidationError('BATCH_CREATE_EVIDENCE_REQUIRED')
            bundle = old_bundle if bundle_id is None else bundle_id
            document = old_document if document_id is None else document_id
            if (not isinstance(bundle, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', bundle)
                    or old_bundle is not None and bundle != old_bundle
                    or document is not None and (type(document) is not int
                                                or not 0 < document < 2**63)
                    or old_document is not None and document != old_document
                    or phase in {'CREATE_DOCUMENT', 'ADD_BUNDLE'} and document is None):
                raise ValidationError('Неподтверждённые идентификаторы результата.')
            next_state = 'DOCUMENT_CREATED' if document_created_only else TRANSITIONS[phase][1]
            self._db.execute('UPDATE operations SET state=?,bundle_id=?,document_id=? WHERE key=?',
                             (next_state, bundle, document, key))

    def unknown_request(self, key: str) -> None:
        with self._transaction():
            self._db.execute("UPDATE operations SET state='OUTCOME_UNKNOWN' "
                             "WHERE key=? AND state='IN_FLIGHT'", (key,))

    # Compatibility API for the previous offline workflow. Storage/locking is shared;
    # permission to make requests belongs exclusively to the corresponding transport.
    def begin_mock(self, key: str, phase: str) -> None:
        self.begin_request(key, phase)

    def confirm_mock(self, key: str, **result) -> None:
        self.confirm_request(key, **result)

    def unknown_mock(self, key: str) -> None:
        self.unknown_request(key)

    def run_mock_step(self, key: str, phase: str, action) -> None:
        """Test-only callback boundary; credentials/responses are never persisted as blobs."""
        self.begin_mock(key, phase)
        failed = False
        try:
            result = action()
            if not isinstance(result, dict) or result.keys() - {'bundle_id', 'document_id'}:
                raise ValidationError('Неожиданные поля mock-ответа.')
            self.confirm_mock(key, **result)
        except Exception:
            if not self._failed:
                self.unknown_mock(key)
            failed = True
        except BaseException:
            if not self._failed:
                self.unknown_mock(key)
            raise
        if failed:
            raise ValidationError('MOCK_OUTCOME_UNKNOWN: повтор записи запрещён.')

    def mark_mock_url_checked(self, key: str, document_id: int) -> None:
        """Record a synthetic read-only check; never construct or persist a guessed URL."""
        if type(document_id) is not int or not 0 < document_id < 2**63:
            raise ValidationError('Нужен подтверждённый mock ID.')
        checkpoint = self.checkpoint(key)
        if (checkpoint['state'] == 'ATTACHED' and checkpoint['document_id'] == document_id
                and checkpoint['url_status'] == 'MOCK_CHECKED'):
            self._check_writable()
            return
        with self._transaction():
            result = self._db.execute(
                "UPDATE operations SET url_status='MOCK_CHECKED' "
                "WHERE key=? AND state='ATTACHED' AND document_id=?", (key, document_id))
            if result.rowcount != 1:
                raise ValidationError('Нет подтверждённого mock документа для проверки URL.')

    def close(self) -> None:
        self._stack.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
