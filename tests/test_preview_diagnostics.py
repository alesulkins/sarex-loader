"""No network: date disambiguation and truthful missing-folder explanations."""

import pytest

from sarex_loader.folder_resolver import FolderRules
from sarex_loader.matching import InspectionIndex, build_match_report
from sarex_loader.preview_messages import explain_file


def match(dates, filenames, *, invalid=False, blocked=False, collision=False):
    rows = [dict(sheet='Реестр', row=i + 2, id_key=str(i + 1), number='35628',
                 office='Офис', contractor='Компания', date=day, month='2026-10',
                 url_class='EMPTY') for i, day in enumerate(dates)]
    if invalid:
        rows[-1]['contractor'] = None
    issues = [{'code': 'DUPLICATE_NUMBER', 'severity': 'error',
               'locations': [{'sheet': 'Реестр', 'row': i + 2} for i in range(len(rows))]}]
    data = dict(registry_type='sk', file='test.xlsx', sha256='synthetic',
                status='REJECTED' if blocked else 'ISSUES', issues=issues, records=rows)
    rules = FolderRules('1', {'Офис': 'Офис'}, {'Компания': 'Компания'}, 'Инспекции')
    index = InspectionIndex([data], {'sk': rules})
    if collision:
        index.groups[0]['unicode_collision'] = True
    entries = [dict(filename=name, reason=None, sha256=str(i), identity=[1, i, 20, 0, 0],
                    size=20) for i, name in enumerate(filenames)]
    return build_match_report(index, entries, 'sk', '-')


NAME = '2026-10-01-Синтетика-35628.pdf'


def test_repeated_number_selects_only_exact_calendar_date():
    result = match(['2026-09-22T11:00:00', '2026-10-01T15:00:00'], [NAME])
    file = result['files'][0]
    assert file['category'] == 'MATCHED'
    assert file['selected_candidate_ids'] == [1]
    assert result['candidate_groups'][0]['candidate_ids'] == [0, 1]


@pytest.mark.parametrize('dates', [
    ['2026-10-01T11:00:00', '2026-10-01T15:00:00'],
    ['2026-09-22', '2026-09-23'], ['2026-10-01', None],
])
def test_same_date_or_unknown_date_never_selects_arbitrarily(dates):
    assert match(dates, [NAME])['files'][0]['category'] == 'AMBIGUOUS'


@pytest.mark.parametrize('options', [{'invalid': True}, {'blocked': True}, {'collision': True}])
def test_date_does_not_bypass_other_blockers(options):
    assert match(['2026-09-22', '2026-10-01'], [NAME], **options)['files'][0][
        'category'] != 'MATCHED'


def test_two_local_inspections_with_same_number_different_dates():
    result = match(['2026-09-22', '2026-10-01'],
                   ['2026-09-22-Синтетика-35628.pdf', NAME])
    assert [f['category'] for f in result['files']] == ['MATCHED', 'MATCHED']
    assert result['duplicate_groups'] == []


def test_local_same_number_same_date_still_blocks():
    result = match(['2026-09-22', '2026-10-01'], [NAME, NAME.replace('Синтетика', 'Другой')])
    assert all(f['category'] == 'AMBIGUOUS' for f in result['files'])


def test_month_message_does_not_claim_contractor_is_missing():
    message = explain_file(dict(status='MONTH_CREATION_REQUIRED', reasons=[],
                                parent_id=42, folder_id=None, month='2026-10', need_folder=True,
                                full_path='Офис → Компания → 2026-10'))
    assert 'Родительская папка существует (ID 42)' in message
    assert 'Добавьте папку месяца' in message
    assert 'Добавьте папку подрядчика' not in message


def test_missing_excel_field_is_named():
    message = explain_file(dict(status='INVALID_REGISTRY_DATA', reasons=['EMPTY_REQUIRED'],
                                excel_candidates=[dict(row=5, office='МГ', contractor=None,
                                                       number='34817', date='2026-09-08')]))
    assert 'Строка Excel 5: не заполнен подрядчик' in message
