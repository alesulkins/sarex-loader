"""Customer's manual observations, not permanent assertions of remote absence.

Always resolve the current snapshot first: a newly existing folder wins over this list.
Other missing months require an operationally accepted current tree.
"""

CONFIRMED_MISSING_MONTHS = frozenset({
    (2066489, '2026-10'),  # СК / ФН Сервис (ОПВ, ПАД) _ Хедмайнер
    (4768006, '2026-10'),  # СК / Хедмайнер (ОВН)
    (2067146, '2026-07'), (2067146, '2026-09'), (2067146, '2026-10'),  # ВК / ТЭЦ
    (4767813, '2026-10'),  # ВК / ФН Сервис (ОВН)/Хедмайнер (ОВН)
    (2067125, '2026-08'), (2067125, '2026-09'), (2067125, '2026-10'),  # ВК / РТИ
})
