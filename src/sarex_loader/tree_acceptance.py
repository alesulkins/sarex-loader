"""User-accepted operational evidence; never an official completeness guarantee."""

POLICY = 'completed-recursive-root-residual-risk-v1'


def operational_tree(index):
    """Fail closed for selective, interrupted, malformed or pagination-limited trees."""
    from sarex_loader.recursive_gateway import validate_observation
    from sarex_loader.safety import ValidationError

    observation = index.observation or {}
    if (observation.get('version') != 3 or observation.get('source') != 'gateway'
            or observation.get('traversal_status') != 'COMPLETED_OBSERVED_TREE'
            or len(observation.get('root_ids', [])) != 1):
        return False
    try:
        validate_observation(observation, index)
    except (ValidationError, KeyError, TypeError, ValueError):
        return False
    root = observation['root_ids'][0]
    if (root not in index.documents or not index.documents[root].is_folder
            or any(root not in d.path_ids for d in index.documents.values())
            or {str(i) for i in index.queried_folders} != set(observation.get('queried_at', {}))):
        return False
    return not any(m.get('more_pages_hint') or m.get('next_page_hint')
                   for m in index.metadata)


def acceptance_summary(index):
    return {'policy': POLICY, 'accepted_for_operational_checks': operational_tree(index),
            'absolute_completeness_proven': False,
            'basis': 'Принят остаточный риск завершённого рекурсивного обхода корня; '
                     'официальная гарантия полноты API отсутствует.'}
