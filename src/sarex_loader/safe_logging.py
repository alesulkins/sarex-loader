"""Allowlisted events: never format user values, exceptions or arbitrary objects."""

import logging
from enum import Enum
from typing import TextIO


class Event(Enum):
    STUB = "stub"
    INVALID = "invalid"
    INTERNAL_ERROR = "internal_error"
    INTERRUPTED = "interrupted"
    AUDIT = "audit"
    API_RESPONSE = "api_response"
    API_ERROR = "api_error"
    API_READ_RESPONSE = 'api_read_response'
    API_SINGLE_TEST_RESPONSE = 'api_single_test_response'


MESSAGES = {
    "stub": "Конфигурация проверена. Операция не реализована; сеть и запись отключены.",
    "invalid": "Параметры отклонены; операция не запускалась.",
    "internal_error": "Внутренняя ошибка; детали скрыты для защиты данных.",
    "interrupted": "Работа прервана; незавершённые отчёты использовать нельзя.",
    "audit": "Локальная проверка завершена. Исходные данные не исправлялись.",
    "api_response": "Ответ тестового API-транспорта получен; удалённый доступ не проверялся.",
    "api_error": "API-проверка завершилась ошибкой; повтор не выполнялся, детали скрыты.",
    'api_read_response': 'Разрешённый read-only/auth ответ получен; право записи не предоставлено.',
    'api_single_test_response': (
        'Ответ одиночного тестового POST получен; нужна итоговая GET-сверка.'),
}


class SafeEventFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # Do not call getMessage(), formatException(), str(args) or repr(extra).
        event = record.msg if type(record.msg) is str else ""
        return MESSAGES.get(event, "Неразрешённое содержимое журнала скрыто.")


class SafeEventHandler(logging.StreamHandler):
    def handleError(self, record: logging.LogRecord) -> None:  # noqa: N802
        # The default logging fallback dumps the original msg/args to stderr.
        # Never fall back to an unfiltered diagnostic, even when the stream fails.
        return


def make_logger(stream: TextIO) -> logging.Logger:
    # An isolated logger avoids root handlers and repeated basicConfig side effects.
    logger = logging.Logger("sarex_loader", level=logging.INFO)
    logger.propagate = False
    handler = SafeEventHandler(stream)
    handler.setFormatter(SafeEventFormatter())
    logger.addHandler(handler)
    return logger
