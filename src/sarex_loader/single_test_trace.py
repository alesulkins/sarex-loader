"""Single-test stage diagnostics: static codes and structural metadata, never raw errors."""

import json
import sys

from sarex_loader.api_models import ApiError

SCOPE_REASONS = frozenset({
    'TEST_SCOPE_DISK_MISMATCH', 'TEST_SCOPE_TARGET_PATH_MISMATCH',
    'TEST_SCOPE_ROOT_MISMATCH', 'TEST_DOCUMENT_MISMATCH', 'TEST_DOCUMENT_PATH_MISMATCH',
    'TEST_PDF_TYPE_OR_KEY_NOT_CONFIRMED', 'UNEXPECTED_DOCUMENT_ATTACHMENT',
    'BUNDLE_FINISH_NOT_CONFIRMED', 'UNEXPECTED_BUNDLE_STATUS',
    'TEST_DOCUMENT_PARENT_MISMATCH', 'TEST_DOCUMENT_BUNDLE_MISMATCH',
    'TEST_DOCUMENT_BUNDLE_UNCONFIRMED',
})
STAGES = frozenset({'AUTH_TOKEN', 'GET_TARGET', 'GET_TEST_ROOT', 'GET_TYPES',
                    'CREATE_BUNDLE', 'UPLOAD_SINGLE', 'UPLOAD_FINISH', 'CREATE_DOCUMENT',
                    'GET_CREATED_DOCUMENT'})


def reason(error):
    if isinstance(error, ApiError):
        return error.code.value
    # Emit a known literal, never interpolate raw exception text or response values.
    for code in SCOPE_REASONS:
        if error.args == (code,):
            return code
    return 'LOCAL_VALIDATION_FAILED'


def run_stage(stage, source, action, verify=None):
    if stage not in STAGES:
        raise ValueError('Unknown diagnostic stage')
    validation_started = False
    error_code = None
    try:
        value = action()
        if verify is not None:
            validation_started = True
            verify(value)
        return value
    except Exception as error:
        error_code = reason(error)
        raise
    except BaseException:
        error_code = 'INTERRUPTED'
        raise
    finally:
        diagnostic = source.response_diagnostic
        if validation_started:
            diagnostic['phase'] = 'SCOPE'
        if error_code and diagnostic.get('reason') in (None, 'OK'):
            diagnostic['reason'] = error_code
        print(json.dumps({**diagnostic, 'stage': stage, 'accepted': error_code is None}),
              file=sys.stderr)
