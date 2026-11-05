"""Append-only metadata checkpoints, separate from upload SQLite and credentials."""

import hashlib
import json
import os
import re
from uuid import uuid4

from sarex_loader.config import checked_path
from sarex_loader.file_safety import read_snapshot
from sarex_loader.process_lock import lock_file
from sarex_loader.reports import _write_bundle
from sarex_loader.safety import ValidationError


class GatewayCheckpoint:
    def __init__(self, path, source, principal, protected, *, resume=False):
        if not re.fullmatch('[0-9a-f]{64}', principal):
            raise ValidationError('Нужна привязка к учётной записи для checkpoint.')
        self.path, self.protected = path.absolute(), protected
        self.header = {'version': 1, 'root_ids': list(source.root_ids),
                       'disk_id': source.disk_id, 'principal_sha256': principal}
        self.records, self.previous_calls = [], []
        self.partial_records = 0
        if any(self.path.is_relative_to(p) or p.is_relative_to(self.path) for p in protected):
            raise ValidationError('Checkpoint должен быть отдельно от входных файлов.')
        if not resume:
            _write_bundle(self.path, {'manifest.json': self.encode(self.header)}, protected)
        checked_path(self.path, directory=True)
        self.fd = os.open(self.path / 'process.lock',
                          os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            checked_path(self.path / 'process.lock', directory=False)
            lock_file(self.fd)
            if resume:
                self._load(source)
        except ValidationError:
            os.close(self.fd)
            raise
        except (KeyError, TypeError, ValueError):
            os.close(self.fd)
            raise ValidationError('Checkpoint повреждён; '
                                  'автоматическое продолжение запрещено.') from None
        except BaseException:
            os.close(self.fd)
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        os.close(self.fd)

    def _load(self, source):
        if self.read_bundle(self.path, 'manifest.json', 4096) != self.header:
            raise ValidationError('Checkpoint принадлежит другому корню или аккаунту.')
        if any(self.path.glob('finished-*')):
            raise ValidationError('Этот обход уже завершён. Начните новый для свежих данных.')
        total = 0
        for entry in sorted(self.path.iterdir()):
            if entry.name in {'manifest.json', 'COMPLETE.json', 'process.lock'}:
                continue
            if not re.fullmatch('(folder|event)-[0-9a-f]{32}', entry.name):
                raise ValidationError('Неизвестный файл checkpoint; требуется проверка.')
            checked_path(entry, directory=True)
            if not (entry / 'COMPLETE.json').exists():
                self.partial_records += 1
                continue  # An interrupted commit is never accepted as a successful read.
            record = self.read_bundle(entry, 'record.json', source.max_response_bytes + 65536)
            total += (entry / 'record.json').stat().st_size
            if total > 512 * 1024**2 or len(self.records) > 10000:
                raise ValidationError('Превышен лимит checkpoint.')
            if entry.name.startswith('folder-'):
                self.records.append(record)
            self.previous_calls.extend(record['calls'])

    @staticmethod
    def encode(value):
        return json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')

    @staticmethod
    def read_bundle(path, name, limit):
        manifest = json.loads(read_snapshot(path / 'COMPLETE.json', 4096))
        data = read_snapshot(path / name, limit)
        if manifest != {name: hashlib.sha256(data).hexdigest()}:
            raise ValidationError('Контрольная сумма checkpoint не совпала.')
        return json.loads(data)

    def save_folder(self, record):
        self._save('folder', record)

    def save_calls(self, calls):
        self._save('event', {'calls': calls})

    def _save(self, prefix, record):
        try:
            _write_bundle(self.path / (prefix + '-' + uuid4().hex),
                          {'record.json': self.encode(record)}, self.protected)
        except ValidationError:
            raise OSError('Checkpoint не сохранён; обход остановлен.') from None

    def finish(self, complete):
        if complete:
            _write_bundle(self.path / ('finished-' + uuid4().hex),
                          {'result.json': b'{"completed_observed_tree":true}'}, self.protected)
