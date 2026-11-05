"""Opt-in safe per-stage diagnostics. Never retry or reinterpret a rejected response."""

import json
import sys

from sarex_loader.api_models import ApiError
from sarex_loader.safety import ValidationError
from sarex_loader.test_target_policy import TEST_PARENT_ID, TEST_ROOT_ID


def emit_stage(stage, client, error=None):
    diagnostic = client.response_diagnostic
    if error is not None and diagnostic.get('reason') in (None, 'OK'):
        diagnostic['reason'] = error.code.value
    print(json.dumps({'stage': stage, **diagnostic,
                      'accepted': error is None}), file=sys.stderr)


class TargetResponseTrace:
    def __init__(self, client):
        self.client = client

    def _call(self, stage, action, identifier):
        try:
            result = action(identifier)
        except ApiError as exc:
            emit_stage(stage, self.client, exc)
            raise
        emit_stage(stage, self.client)
        return result

    def get_document(self, identifier):
        if identifier not in (TEST_PARENT_ID, TEST_ROOT_ID):
            raise ValidationError('Недопустимая цель диагностики.')
        stage = 'GET_TARGET' if identifier == TEST_PARENT_ID else 'GET_TEST_ROOT'
        return self._call(stage, self.client.get_document, identifier)

    def get_ancestors(self, identifier):
        if identifier != TEST_PARENT_ID:
            raise ValidationError('Недопустимая цель диагностики предков.')
        return self._call('GET_TARGET_ANCESTORS', self.client.get_ancestors, identifier)
