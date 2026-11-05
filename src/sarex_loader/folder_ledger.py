"""Permanent month-creation intents using the existing private SQLite storage adapters."""

import json
from pathlib import Path

from sarex_loader.api_models import valid_id
from sarex_loader.folder_resolver import calendar_month, safe_component
from sarex_loader.journal import SCHEMA, Journal, canonical, fingerprint
from sarex_loader.recursive_gateway import PROFILE_ROOTS
from sarex_loader.safety import ValidationError
from sarex_loader.single_test_scope import TEST_DISK_ID

CONTEXT = fingerprint({'mode': 'month-folder-ledger-v1', 'disk_id': TEST_DISK_ID})


def journal_path():
    return Path.home() / '.sarex-loader-folder-journal'


def validate_plan(plan):
    path = plan.get('parent_path', [])
    root = plan.get('root_id')
    if (set(plan) != {'disk_id', 'root_id', 'parent_id', 'parent_path', 'name', 'month',
                     'full_path'}
            or plan['disk_id'] != TEST_DISK_ID
            or root not in {r[0] for r in PROFILE_ROOTS.values()}
            or type(path) is not list or not path or any(not valid_id(i) for i in path)
            or len(path) != len(set(path)) or root not in path
            or not valid_id(plan['parent_id']) or path[-1] != plan['parent_id']
            or path[-1] == root
            or any(i in path for i in {2093037, *[r[0] for r in PROFILE_ROOTS.values()
                                                 if r[0] != root]})
            or not safe_component(plan['name'])
            or calendar_month(plan['name']) is None
            or calendar_month(plan['name']) != plan['month']
            or not isinstance(plan['full_path'], str) or not plan['full_path']):
        raise ValidationError('Небезопасный план месячной папки или родитель вне корня.')


def operation_key(plan):
    validate_plan(plan)
    return fingerprint({k: plan[k] for k in ('disk_id', 'parent_id', 'month')})


class FolderLedger(Journal):
    """Separate namespace/schema semantics; never opens a historical upload journal.

    Reuses Journal's locked directory, Windows handles, FULL transactions and busy_timeout.
    A candidate is retained in document_id even when validation or the following GET fails.
    """

    def __init__(self, protected):
        super().__init__(journal_path(), protected)
        try:
            if not self._db.execute("SELECT 1 FROM meta WHERE key='context'").fetchone():
                with self._transaction():
                    self._db.execute("INSERT INTO meta VALUES ('context', ?)", (CONTEXT,))
            self.check_safe()
        except BaseException:
            self.close()
            raise

    def _validate_database(self):
        found = dict(self._db.execute(
            "SELECT name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"))
        meta = dict(self._db.execute('SELECT key,value FROM meta'))
        if (found != SCHEMA or self._db.execute('PRAGMA quick_check').fetchall() != [('ok',)]
                or meta != {'schema': '1', 'context': CONTEXT}
                or self._db.execute('SELECT count(*) FROM operations').fetchone()[0] > 150_000):
            raise ValidationError('Некорректный или чужой журнал создания папок.')
        for key, payload, state, phase, bundle, identifier, url in self._db.execute(
                'SELECT * FROM operations'):
            plan = json.loads(payload)
            if (operation_key(plan) != key or canonical(plan) != payload
                    or len(payload) > 32768 or bundle is not None or url != 'UNVERIFIED'
                    or state not in {'PLANNED', 'IN_FLIGHT', 'OUTCOME_UNKNOWN',
                                     'CREATED', 'FORBIDDEN'}
                    or phase != (None if state == 'PLANNED' else 'CREATE_DOCUMENT')
                    or identifier is not None and not valid_id(identifier)
                    or state == 'CREATED' and identifier is None
                    or state in {'PLANNED', 'FORBIDDEN'} and identifier is not None):
                raise ValidationError('Некорректное состояние создания папки.')

    def check_safe(self):
        self._verify_directory()
        if any(c['state'] in {'IN_FLIGHT', 'OUTCOME_UNKNOWN'}
               for c in self.checkpoints().values()):
            raise ValidationError('OUTCOME_UNKNOWN: создание папок требует ручной сверки; '
                                  'новые операции запрещены.')

    def reserve(self, plan):
        self.check_safe()
        key = operation_key(plan)
        encoded = canonical(plan)
        if len(encoded) > 32768:
            raise ValidationError('Слишком большой план папки.')
        prior = self._db.execute('SELECT payload FROM operations WHERE key=?', (key,)).fetchone()
        if prior and prior != (encoded,):
            raise ValidationError('Имя или путь ранее запланированной папки изменились.')
        if not prior:
            with self._transaction():
                self._db.execute("INSERT OR IGNORE INTO meta VALUES ('context', ?)", (CONTEXT,))
                self._db.execute('INSERT INTO operations VALUES (?,?,?,NULL,NULL,NULL,?)',
                                 (key, encoded, 'PLANNED', 'UNVERIFIED'))
        return key

    def begin(self, key):
        self.check_safe()
        if self.checkpoint(key)['state'] not in {'PLANNED', 'FORBIDDEN'}:
            raise ValidationError('Повторное создание папки запрещено.')
        with self._transaction():
            self._db.execute("UPDATE operations SET state='IN_FLIGHT', phase='CREATE_DOCUMENT' "
                             'WHERE key=?', (key,))

    def candidate(self, key, identifier):
        if not valid_id(identifier) or self.checkpoint(key)['state'] != 'IN_FLIGHT':
            raise ValidationError('Недопустимый кандидат создания папки.')
        with self._transaction():
            self._db.execute('UPDATE operations SET document_id=? WHERE key=?', (identifier, key))

    def finish(self, key, state):
        checkpoint = self.checkpoint(key)
        if (checkpoint['state'] != 'IN_FLIGHT'
                or state not in {'CREATED', 'OUTCOME_UNKNOWN', 'FORBIDDEN'}
                or state == 'CREATED' and not valid_id(checkpoint['document_id'])
                or state == 'FORBIDDEN' and checkpoint['document_id'] is not None):
            raise ValidationError('Недопустимый переход журнала папки.')
        with self._transaction():
            self._db.execute('UPDATE operations SET state=? WHERE key=?', (state, key))
