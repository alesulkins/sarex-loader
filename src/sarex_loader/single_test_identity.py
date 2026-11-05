"""Closed set of explicitly authorized tests, not a factory for retry identities."""

from sarex_loader.safety import ValidationError

INDEPENDENT_OPERATION_ID = '9e67146e-3ea3-4a76-8515-1c8acc417f72'
INDEPENDENT_FILENAME = f'sarex-loader-test-{INDEPENDENT_OPERATION_ID}.pdf'
THIRD_OPERATION_ID = '8cfb236a-7c50-40df-b512-31ed5cb3b8cb'
THIRD_FILENAME = f'sarex-loader-test-{THIRD_OPERATION_ID}.pdf'
# Reserved preparation identity, not an automatically registered or approved live run.
EXCEL_OPERATION_ID = 'c2e0e124-9750-4f39-9b6d-64b24e0d58bc'
OLD_DISK_ID = '25cb6f03-454d-4bc6-aeb6-2808c3a2b68b'


def validate_operation_id(value):
    if value is not None and (type(value) is not str or value not in {
            INDEPENDENT_OPERATION_ID, THIRD_OPERATION_ID, EXCEL_OPERATION_ID}):
        raise ValidationError('INDEPENDENT_OPERATION_NOT_AUTHORIZED')


def independent_filename(value):
    validate_operation_id(value)
    if value is None:
        raise ValidationError('INDEPENDENT_CONFIG_REQUIRED')
    return f'sarex-loader-test-{value}.pdf'
