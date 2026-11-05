"""Optional post-upload month creation; never uploads into a newly created folder."""

import sys
from contextlib import redirect_stdout

from sarex_loader.api_client import ApiSettings, SarexClient
from sarex_loader.api_models import ApiError
from sarex_loader.folder_ledger import operation_key, validate_plan
from sarex_loader.folder_transport import FolderHTTPSTransport
from sarex_loader.gateway_tree import gateway_login
from sarex_loader.https_transport import ReadOnlyHTTPSTransport
from sarex_loader.monthly_folders import infer_month_name
from sarex_loader.profile_auth import use_settings
from sarex_loader.read_only_policy import DOCUMENTATION_BASE, ReadOnlyPolicy
from sarex_loader.safety import ValidationError
from sarex_loader.tree_acceptance import operational_tree
from sarex_loader.upload_preview import full_path


def prepare_plans(config, index, report):
    if not operational_tree(index):
        raise ValidationError('Создание папок требует завершённого обхода без ошибок.')
    plans = {}
    for file in report['files']:
        if (file['category'] != 'MATCHED' or len(file['excel_candidates']) != 1
                or file.get('folder_status') != 'MONTH_CREATION_REQUIRED'
                or set(file['reasons']) - {'MONTH_CREATION_REQUIRED'}
                or not file.get('naming')
                or file['naming']['status'] != 'MONTH_NAME_INFERRED'):
            continue
        parent = index.documents[file['parent_id']]
        naming = infer_month_name(list(index.children.get(parent.id, {}).values()), file['month'],
                                  parent_id=parent.id, parent_path=parent.path_ids)
        if (not parent.is_folder or parent.id not in index.queried_folders
                or naming['status'] != 'MONTH_NAME_INFERRED'
                or naming['name'] != file['naming']['name']):
            continue
        plan = {'disk_id': config.tree.disk_id, 'root_id': config.tree.root_ids[0],
                'parent_id': parent.id, 'parent_path': list(parent.path_ids),
                'month': file['month'], 'name': naming['name'],
                'full_path': full_path(index, parent.id) + ' → ' + naming['name']}
        validate_plan(plan)
        plans[operation_key(plan)] = plan
    return sorted(plans.values(), key=lambda p: (p['parent_id'], p['month']))


def _read_client(provider, identifier):
    return SarexClient(ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',)),
                       transport=ReadOnlyHTTPSTransport(ReadOnlyPolicy((identifier,)),
                                                       confirmed=True),
                       token_provider=provider, read_only_network_enabled=True)


def _verify_document(provider, identifier, name, path, disk):
    doc = _read_client(provider, identifier).get_document(identifier)
    if (not doc.is_folder or doc.name != name or doc.disk_id != disk
            or doc.path != '.'.join(map(str, path))):
        raise ValidationError('GET не подтвердил имя, диск или полный путь папки.')
    return doc


def execute(plans, config, index, ledger, provider, *, verify_sources):
    from sarex_loader.production_upload import fresh_children

    outcomes = []
    for plan in plans:
        ledger.check_safe()
        validate_plan(plan)
        key = ledger.reserve(plan)
        try:
            verify_sources()
            root = index.documents[plan['root_id']]
            parent = index.documents[plan['parent_id']]
            if (parent.path_ids[:len(root.path_ids)] != root.path_ids
                    or list(parent.path_ids) != plan['parent_path']):
                raise ValidationError('Путь родителя изменился.')
            _verify_document(provider, root.id, root.name, root.path_ids, plan['disk_id'])
            _verify_document(provider, parent.id, parent.name, parent.path_ids, plan['disk_id'])
            children = fresh_children(config, index, parent.id, provider)
            naming = infer_month_name(list(children.values()), plan['month'],
                                      parent_id=parent.id, parent_path=parent.path_ids)
            if naming['status'] == 'MONTH_ALREADY_EXISTS':
                doc = children[naming['folder_id']]
                _verify_document(provider, doc.id, doc.name, doc.path_ids, plan['disk_id'])
                outcomes.append({**plan, 'status': 'ALREADY_EXISTS', 'folder_id': doc.id,
                                 'description': 'Месячная папка уже существует; POST не выполнен.'})
                continue
            if (naming['status'] != 'MONTH_NAME_INFERRED' or naming['name'] != plan['name']
                    or ledger.checkpoint(key)['state'] == 'CREATED'):
                raise ValidationError('Имя месяца изменилось, неоднозначно или ранее созданная '
                                      'папка отсутствует в свежем ответе.')
        except (ApiError, ValidationError) as exc:
            outcomes.append({**plan, 'status': 'SKIPPED', 'description':
                             'Папка пропущена при проверке: ' + str(exc)})
            continue
        transport = FolderHTTPSTransport(ledger, key, plan, confirmed=True)
        client = SarexClient(ApiSettings(DOCUMENTATION_BASE, ('https://api.sarex.io',)),
                             transport=transport, token_provider=provider,
                             folder_network_enabled=True)
        ledger.begin(key)  # Durable intent BEFORE any possible network effect.
        try:
            created = client.create_month_folder(disk_id=plan['disk_id'],
                                                 parent_id=parent.id, name=plan['name'])
            if created.id in plan['parent_path']:
                raise ValidationError('Ответ создания повторяет ID родителя или предка.')
            verified = _verify_document(provider, created.id, plan['name'],
                                        [*plan['parent_path'], created.id], plan['disk_id'])
            if ledger.checkpoint(key)['document_id'] != verified.id:
                raise ValidationError('ID ответа создания не сохранён в журнале.')
        except Exception:
            denied = transport.denied and ledger.checkpoint(key)['document_id'] is None
            ledger.finish(key, 'FORBIDDEN' if denied else 'OUTCOME_UNKNOWN')
            outcomes.append({**plan, 'status': 'FORBIDDEN' if denied else 'OUTCOME_UNKNOWN',
                             'description': 'Недостаточно прав для создания папки' if denied
                             else 'Исход создания неизвестен; повтор POST запрещён.'})
            if not denied:
                break
        else:
            ledger.finish(key, 'CREATED')
            outcomes.append({**plan, 'status': 'CREATED', 'folder_id': verified.id,
                             'description': 'Папка создана и подтверждена GET.'})
    return outcomes


def finish(plans, config, index, ledger, settings, *, verify_sources, ask=input):
    if not settings.allow_folder_creation or not plans:
        return []
    if not operational_tree(index):
        raise ValidationError('Неполное дерево: создание папок запрещено.')
    with redirect_stdout(sys.__stdout__):
        print('Не найдены необходимые месячные папки:')
        for plan in plans:
            print(plan['full_path'] + f" (parent_id={plan['parent_id']})")
        answer = ask('Создать отсутствующие папки? (да/нет) ').strip().casefold()
    if answer != 'да':
        return [{**p, 'status': 'DECLINED', 'description':
                 'Создание отменено. Создайте папку самостоятельно или повторите запуск.'}
                for p in plans]
    with use_settings(settings), gateway_login() as provider:
        outcomes = execute(plans, config, index, ledger, provider, verify_sources=verify_sources)
    for outcome in outcomes:
        print(outcome['full_path'] + ': ' + outcome['description'])
    if any(o['status'] == 'CREATED' for o in outcomes):
        print('Папки созданы. Повторно запустите программу той же командой '
              'для загрузки оставшихся PDF. При частичном успехе проверьте список результатов.')
    return outcomes
