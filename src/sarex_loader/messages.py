"""Russian presentation; machine codes remain stable and never contain secrets."""

import json
import re
import sys

LABELS = {
    "PDF_CONTRACTOR_MISMATCH": "Подрядчик в имени PDF противоречит подрядчику Excel; файл пропущен",
    "PDF_OFFICE_MISMATCH": "Офис в имени PDF противоречит офису Excel; файл пропущен",
    "PDF_PROJECT_SCOPE_MISMATCH": (
        "Обозначения ОВН/НК/ОПВ/ПАД и других участков противоречат маршруту"),
    "PDF_MG_CONTEXT_UNVERIFIED": "В имени PDF не подтверждено МГ для отдельной ветки РСУ/ЮСР/БиДжи",
    "PDF_DESTINATION_BRANCH_MISMATCH": "Папка находится вне подтверждённой ветки подрядчика",
    "EXPLICIT_NUMBER_CONFLICT": (
        "Исходный и исправленный номера ведут к разным строкам Excel"
    ),
    "EXCEL_DATE_INVALID": "Дата Excel отсутствует или некорректна",
    "DATE_MISMATCH": "Дата в имени PDF отличается от даты Excel; загрузка запрещена",
    "MONTH_EXCEPTION_CONFLICT": (
        "Подтверждённая последовательность РСУ.МГ изменилась; нужна проверка"
    ),
    "MATCHED": "Однозначно сопоставлен с Excel",
    "LOCAL_MATCH": "Локальное соответствие; требуется проверка перед загрузкой",
    "READY": "Готов к загрузке",
    "READY_BY_METADATA": "Подходит по метаданным; перед загрузкой нужна проверка PDF",
    "FOLDER_CREATION_DISABLED": "Создание папок отключено; PDF пропущен до появления папки",
    "NOT_FOUND": "Номер PDF не найден в реестре",
    "AMBIGUOUS": "Неоднозначное сопоставление или дубликат",
    "AMBIGUOUS_ROUTE": "Маршрут неоднозначен",
    "AMBIGUOUS_FOLDER": "Найдено несколько подходящих папок",
    "INVALID_DATA": "Некорректные исходные данные",
    "INVALID_FILENAME": "Имя или состояние PDF не прошло проверку",
    "INVALID_REGISTRY_DATA": "Строка Excel или правила маршрута не прошли проверку",
    "EXISTING_URL": "В Excel уже есть URL; повторная загрузка запрещена",
    "REMOTE_DOCUMENT_EXISTS": "Совпадение имени или номера уже есть в Sarex",
    "FOLDER_NOT_RESOLVED_IN_SNAPSHOT": "Папка не найдена в полученных метаданных",
    "TREE_METADATA_UNAVAILABLE": "Свежие метаданные нужной папки недоступны",
    "TREE_COMPLETENESS_UNVERIFIED": "Полнота списка детей Gateway не подтверждена",
    "RESOLVED_IN_SNAPSHOT": "Папка существует; ID и путь найдены в свежем индексе",
    "MONTH_CREATION_REQUIRED": "Требуется создание месячной папки",
    "MONTH_ABSENCE_UNVERIFIED": "Месяц не найден в выдаче; её полнота не подтверждена",
    "LOCAL_MOVE_NOT_PROVEN": "Номер извлечён ненадёжно или есть другая ошибка; PDF не перемещён",
    "TREE_FOLDER_BUDGET_EXCEEDED": "Достигнут лимит папок; рекурсивный обход не завершён",
    "TREE_TIME_BUDGET_EXCEEDED": "Достигнут лимит времени; обход не завершён",
    "TREE_ROOT_PROFILE_MISMATCH": "Название корня Sarex не соответствует профилю СК/ВК",
    "TREE_INTERRUPTED": "Обход прерван пользователем; сохранён частичный индекс",
    "TREE_PAGINATION_UNSUPPORTED": (
        "Ответ требует дополнительных страниц; схема API не подтверждена"),
    "MONTH_NAME_INFERRED": "Название месяца рассчитано по соседним папкам",
    "MONTH_NAMING_AMBIGUOUS": "Формат названия месяца неоднозначен или недостаточно примеров",
    "MONTH_NUMBERING_INCONSISTENT": "Порядковые номера не соответствуют календарным месяцам",
    "DUPLICATE_MONTH": "Один месяц представлен несколькими папками",
    "DUPLICATE_MONTH_PREFIX": "Порядковый номер месяца повторяется или занят",
    "MONTH_NAME_COLLISION": "Название новой папки уже занято",
    "MONTH_ALREADY_EXISTS": "Папка этого месяца уже существует",
    "PDF_EXCEL_DATE_CONFLICT": "Дата в имени PDF отличается от даты Excel; загрузка запрещена",
    "PDF_DATE_INVALID": "Некорректная дата в имени PDF; загрузка запрещена",
    "PDF_CONTENT_NOT_VERIFIED": "Содержимое и контрольная сумма PDF не проверялись",
    "CONTRACTOR_MAPPING_MISSING": "Не подтверждено соответствие подрядчика папке Sarex",
    "OFFICE_MAPPING_MISSING": "Не подтверждено соответствие офиса папке Sarex",
    "ROUTE_NOT_CONFIGURED": "Для этого контекста нет подтверждённого маршрута",
    "NOT_FOUND_IN_EXPORT": "Подходящий PDF не найден в полученном индексе",
    "NOT_COVERED_BY_EXPORT": "Строка не покрыта подтверждёнными метаданными маршрута",
    "CLOUD_PLACEHOLDER": "PDF ещё не скачан из OneDrive на компьютер",
    "OUTCOME_UNKNOWN": "Результат изменяющего запроса неизвестен; повтор запрещён",
    "MOCK_STOPPED": "Тест остановлен после текущего файла; журнал и копия Excel сохранены",
    "CREATED": "Папка создана и проверена",
    "FORBIDDEN": "Ошибка: недостаточно прав для создания папки",
    "DECLINED": "Создание отменено; создайте папку самостоятельно",
    "SIMULATION_ONLY": "Создание доступно только в изолированной симуляции",
    "CLEAN": "Проверка завершена без замечаний",
    "ISSUES": "Проверка завершена с замечаниями",
    "REGISTRY_INVALID_REGISTRY_DATA": "Данные строки Excel не позволяют подтвердить маршрут",
    "REGISTRY_NOT_FOUND": "Соответствующая строка Excel не найдена",
    "REGISTRY_AMBIGUOUS": "Номер соответствует нескольким строкам Excel",
    "DUPLICATE_NUMBER": "Номер инспекции повторяется среди локальных PDF",
    "DUPLICATE_UNICODE_NAME": "Имена PDF совпадают после нормализации символов",
    "DUPLICATE_HASH": "Найдены PDF с одинаковым содержимым",
    "DUPLICATE_INODE": "Несколько путей указывают на один локальный файл",
    "EMPTY_REQUIRED": "В Excel не заполнено обязательное поле",
    "EXISTING_URL_REQUIRES_REVIEW": "В Excel уже записана ссылка; требуется ручная проверка",
    "URL_READY": "Ссылка найдена и подготовлена для новой копии Excel",
    "FILLED": "Ссылка добавлена в новую копию Excel",
    "TREE_AUTH_FAILED": "Не удалось войти в Sarex; проверьте учётные данные и доступ",
    "TREE_SECURE_LOGIN_UNAVAILABLE": "Защищённый вход недоступен; запустите из терминала",
    "TREE_GATEWAY_SCOPE_INVALID": "Область чтения Gateway не прошла проверку",
    "TREE_REQUEST_SCOPE_UNVERIFIED": "Запрошенная папка не входит в подтверждённую область",
    "TREE_TOKEN_TIME_BUDGET_EXCEEDED": "Время безопасного использования токена истекло",
    "TIMEOUT": "Сервер не ответил в установленный срок; метаданные папки недоступны",
    "ACCESS_DENIED": "Сервер отказал в доступе к запрошенным данным",
    "NETWORK_ERROR": "Не удалось получить ответ сервера; проверьте соединение",
}


def describe(code):
    text = str(code)
    key = text.split(":", 1)[0]
    if key in LABELS:
        return LABELS[key]
    if re.search("[А-Яа-я]", text):
        return text
    return "Требуется проверка; диагностический код: " + key


def emit_report(report):
    value = dict(report)
    summary = report.get("summary", {})
    value["сообщение"] = "Обработка завершена. Проверьте итоговые отчёты и причины пропусков."
    value["описания_статусов"] = {k: describe(k) for k in summary}
    rendered = json.dumps(value, ensure_ascii=False)
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    print(rendered.encode(encoding, errors="backslashreplace").decode(encoding))
