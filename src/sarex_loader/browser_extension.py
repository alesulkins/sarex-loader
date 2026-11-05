"""Bounded stdio client for the official Playwright MCP, not a Sarex API client."""

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from sarex_loader.safety import ValidationError

MAX_MESSAGE = 16 * 1024**2


class ExtensionReader:
    """One user-approved extension connection per run; no cookies or token export."""

    def __init__(self, disk_id, max_response_bytes):
        self.disk_id = disk_id
        self.limit = max_response_bytes
        self.process = None
        self.temp = None
        self.counter = 0
        self.messages = queue.Queue(maxsize=32)
        self.tool = None
        self.first = True

    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sarex-tree-mcp-')
        # Do not inherit extension bypass tokens, traces, debug logs or Node hooks.
        env = {k: v for k, v in os.environ.items()
               if k in {'PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'SYSTEMROOT', 'USERPROFILE'}}
        try:
            self.process = subprocess.Popen(  # noqa: S603 — fixed installed module, no shell
                [sys.executable, '-B', '-m', 'playwright', 'mcp', '--extension',
                 '--snapshot-mode', 'none', '--codegen', 'none', '--no-webmcp',
                 '--console-level', 'error', '--output-dir', self.temp.name],
                cwd=self.temp.name, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL)
            threading.Thread(target=self._read, daemon=True).start()
            self._call('initialize', {'protocolVersion': '2024-11-05', 'capabilities': {},
                                      'clientInfo': {'name': 'Sarex read-only metadata',
                                                     'version': '1.0'}})
            self._send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
            listed = self._call('tools/list', {})
            names = {'browser_run_code', 'browser_run_code_unsafe'}
            self.tool = next((t['name'] for t in listed['tools'] if t['name'] in names), None)
            if self.tool is None:
                raise ValidationError('TREE_EXTENSION_VERSION_UNSUPPORTED')
            print('В окне Playwright Welcome выберите Allow & select у вкладки '
                  '«Документация» Sarex. Токен расширения не нужен.', file=sys.stderr)
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise ValidationError('TREE_EXTENSION_START_FAILED: нужен Playwright 1.64.1 '
                                  'и официальное расширение в текущем Chrome.') from None

    def _read(self):
        try:
            while line := self.process.stdout.readline(MAX_MESSAGE + 1):
                if len(line) > MAX_MESSAGE:
                    break
                self.messages.put(json.loads(line), timeout=1)
        except (OSError, ValueError, queue.Full):
            pass
        try:
            self.messages.put(None, timeout=1)
        except queue.Full:
            pass

    def _send(self, value):
        self.process.stdin.write(json.dumps(value, ensure_ascii=True).encode() + b'\n')
        self.process.stdin.flush()

    def _call(self, method, params, timeout=30):
        self.counter += 1
        try:
            self._send({'jsonrpc': '2.0', 'id': self.counter, 'method': method, 'params': params})
            end = time.monotonic() + timeout
            while True:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise queue.Empty
                message = self.messages.get(timeout=remaining)
                if type(message) is not dict or 'error' in message:
                    raise ValueError
                if message.get('id') == self.counter:
                    return message['result']
        except (OSError, ValueError, KeyError, queue.Empty):
            raise ValidationError('TREE_EXTENSION_CONNECTION_FAILED: проверьте подтверждение '
                                  'вкладки; автоматического повтора нет.') from None

    def fetch(self, folder_id):
        script = Path(__file__).with_name('browser_extension.js').read_text(encoding='utf-8')
        # Only fixed packaged code and validated integer IDs enter the interpreter.
        params = {'action': 'fetch', 'disk': self.disk_id, 'folder': folder_id, 'limit': self.limit}
        code = f'async page => await ({script})(page, {json.dumps(params)})'
        for attempt in range(2):
            result = self._call('tools/call', {'name': self.tool, 'arguments': {'code': code}},
                                timeout=360 if self.first else 120)
            self.first = False
            try:
                return extension_result(result)
            except ValidationError as error:
                # Repeat only the identical guarded UI read, once. HTTP/access,
                # scope, workers, malformed data and connection errors fail closed.
                # This code never invokes the upload transport or a journal.
                if attempt or not str(error).startswith((
                        'TREE_EXTENSION_GATEWAY_TIMEOUT:', 'TREE_EXTENSION_NAVIGATION_FAILED:')):
                    raise
                print(f'Повтор чтения папки {folder_id}: ответ UI не получен; попытка 2/2.',
                      file=sys.stderr)

    def __exit__(self, *_args):
        if self.process is not None:
            try:
                if self.tool is not None and self.process.poll() is None:
                    code = ('async page => { const state = page.context().__sarexMetadata; '
                            'if (state) { delete page.context().__sarexMetadata; '
                            'await state.ownedPage.close(); } return {closed:true}; }')
                    self._call('tools/call', {'name': self.tool, 'arguments': {'code': code}},
                               timeout=10)
            except (ValidationError, OSError):
                pass
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
            for stream in (self.process.stdin, self.process.stdout):
                stream.close()
        if self.temp is not None:
            self.temp.cleanup()


def extension_result(result):
    """Never expose automatic MCP console/page/exception sections to the caller."""
    try:
        text = '\n'.join(c.get('text', '') for c in result.get('content', []))
        if result.get('isError'):
            allowed = ('WRONG_TAB', 'SERVICE_WORKER_PRESENT', 'HTTP_REJECTED', 'RESPONSE_TOO_LARGE',
                       'CONTENT_TYPE_INVALID', 'SCOPE_INVALID', 'GATEWAY_TIMEOUT', 'PAGE_CLOSED',
                       'WORKER_CHECK_FAILED', 'NAVIGATION_FAILED', 'BODY_FAILED', 'JSON_INVALID')
            code = next((c for c in allowed if f'SAREX_TREE_{c}' in text), 'BROWSER_FAILED')
            raise ValidationError(f'TREE_EXTENSION_{code}: индекс не обновлён.')
        value = text.split('### Result\n', 1)[1].split('\n### ', 1)[0].strip()
        result = json.loads(value)
        if type(result) is not dict or set(result) != {
                'folder_id', 'received_at', 'status', 'blocked_mutations', 'payload'}:
            raise ValueError
        return result
    except ValidationError:
        # ValidationError subclasses ValueError: preserve our safe reason code,
        # while still discarding malformed JSON and arbitrary browser diagnostics.
        raise
    except (AttributeError, TypeError, ValueError, IndexError):
        raise ValidationError('TREE_EXTENSION_RESPONSE_INVALID') from None
