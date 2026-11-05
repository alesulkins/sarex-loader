"""Repeatable read-only sample/full route check; no PDF bytes, SQLite or upload imports."""

import json
import sys
from collections import Counter
from pathlib import Path

from sarex_loader.audit import audit_registry
from sarex_loader.cli import SafeParser
from sarex_loader.recovery_config import load_recovery_config
from sarex_loader.reports import _write_bundle
from sarex_loader.safety import ValidationError
from sarex_loader.tree_source import (
    read_tree,
    resolve_observed_path,
    snapshot_payloads,
    tree_snapshot,
    tree_summary,
)


def required_paths(config):
    paths, registries = set(), []
    for registry in config.registries:
        audit = audit_registry(registry)
        rules = config.routes[registry.inspection_type]
        own, problems = set(), Counter()
        for record in audit['records']:
            if record['url_class'] != 'EMPTY':
                continue
            proposal, error = rules.propose(record)
            if error:
                problems[error] += 1
            else:
                own.add((int(rules.root_id), tuple(proposal['components'])))
        paths.update(own)
        registries.append({'kind': registry.inspection_type, 'root_id': int(rules.root_id),
                           'rows': len(audit['records']), 'sha256': audit['sha256'],
                           'required_paths': len(own), 'route_errors': dict(problems)})
    return paths, registries


def check(config, output, *, full=False, sample_per_registry=2, read=False):
    if (config.tree is None or config.tree.source != 'gateway'
            or type(full) is not bool or type(read) is not bool
            or type(sample_per_registry) is not int or not 1 <= sample_per_registry <= 10):
        raise ValidationError('GATEWAY_CHECK_CONFIG_INVALID')
    if output.exists() or output.is_symlink() or output.is_relative_to(config.root):
        raise ValidationError('GATEWAY_CHECK_NEW_OUTPUT_REQUIRED')
    paths, registries = required_paths(config)
    if not full:
        selected = set()
        for root in {root for root, _ in paths}:
            ordered = sorted((p for p in paths if p[0] == root),
                             key=lambda p: (p[1][-1], p[1]), reverse=True)
            selected.update(ordered[:sample_per_registry])
        paths = selected
    prefixes = {(root, parts[:i]) for root, parts in paths for i in range(len(parts) + 1)}
    report = {'mode': 'GATEWAY_READ_ONLY_CHECK', 'read_enabled': read, 'full': full,
              'registries': registries, 'selected_paths': len(paths),
              'get_upper_bound': len(prefixes), 'resource_mutations': 0,
              'pdf_contents_read': False, 'sqlite_opened': False}
    if read:
        index = read_tree(config.tree, paths, allow_browser=True)
        resolutions = []
        for root, parts in sorted(paths):
            result = resolve_observed_path(index, root, parts)
            resolutions.append({'root_id': root, 'components': parts, 'status': result.status,
                                'folder_id': result.folder_id, 'path_ids': result.path_ids})
        report.update(tree=tree_summary(config.tree, index), routes=resolutions,
                      route_results=dict(Counter(r['status'] for r in resolutions)),
                      observed_folders=sum(d.is_folder for d in index.documents.values()),
                      observed_pdf_ids=sum(not d.is_folder and d.name.lower().endswith('.pdf')
                                           for d in index.documents.values()))
        if required_paths(config)[1] != registries:
            raise ValidationError('INPUT_CHANGED')
        snapshot = tree_snapshot(config.tree, index)
        payloads = snapshot_payloads(snapshot, config.tree.max_response_bytes) if snapshot else {}
    else:
        payloads = {}
    payloads['gateway-check.json'] = json.dumps(report, ensure_ascii=False, indent=2).encode()
    _write_bundle(output, payloads, [config.root])
    return report


def main(argv=None):
    parser = SafeParser(description='Gateway: только метаданные нужных маршрутов СК/ВК.')
    parser.add_argument('--recovery-config', required=True)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--full', action='store_true')
    parser.add_argument('--sample-per-registry', type=int, default=2)
    parser.add_argument('--read-tree', action='store_true')
    try:
        args = parser.parse_args(argv)
        report = check(load_recovery_config(args.recovery_config),
                       Path(args.output_dir).absolute(), full=args.full,
                       sample_per_registry=args.sample_per_registry, read=args.read_tree)
        print(json.dumps(report, ensure_ascii=True))
        return 3 if any(k != 'RESOLVED_IN_SNAPSHOT' and v
                        for k, v in report.get('route_results', {}).items()) else 0
    except ValidationError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print('Чтение прервано; изменений Sarex нет.', file=sys.stderr)
        return 130
    except Exception:
        print('GATEWAY_CHECK_FAILED: детали скрыты.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
