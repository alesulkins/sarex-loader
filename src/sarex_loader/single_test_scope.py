"""User-confirmed Documentation disk and DevTools path for ONE test target."""

from sarex_loader.api_models import Document
from sarex_loader.safety import ValidationError
from sarex_loader.test_target import disk_id_format

# Corrected from the user's GET /documentations/api/v1/disks result.
# Its document_id=1600045 is the first ID in the confirmed target path.
# This is NOT the disk UUID embedded in the separately allowed Gateway route.
TEST_DISK_ID = '25cbff03-454d-4b6c-aeb6-2808c3a2b68b'
TEST_ROOT_ID = 2093037
TEST_PARENT_ID = 7915046
TEST_PATH_IDS = (1600045, 2062798, 2093037, 7699846, 7915038, 7915041, 7915042, 7915043, 7915046)
TEST_PATH = '.'.join(map(str, TEST_PATH_IDS))
ROOT_PATH = '.'.join(map(str, TEST_PATH_IDS[:3]))
TEST_FILENAME = 'sarex-loader-single-test.pdf'


def verify_pdf_type(types, config):
    if sum(t.name == config.document_type and any(
            f.key == config.key and f.file is True and f.can_upload is True
            for f in t.fields) for t in types) != 1:
        raise ValidationError('TEST_PDF_TYPE_OR_KEY_NOT_CONFIRMED')


def check_disk(value):
    # The exact target/disk association was manually confirmed. Missing/empty disk
    # metadata is not an error in THIS scope; a present contradictory value always is.
    if value in (None, ''):
        return
    if disk_id_format(value) not in {'CANONICAL_UUID', 'UUID_HEX_CASE'} \
            or value.lower() != TEST_DISK_ID:
        raise ValidationError('TEST_SCOPE_DISK_MISMATCH')


def verify_target_document(document: Document, *, expected_path=TEST_PATH_IDS):
    if (type(document) is not Document or document.id != expected_path[-1]
            or document.is_folder is not True
            or document.path != '.'.join(map(str, expected_path))):
        raise ValidationError('TEST_SCOPE_TARGET_PATH_MISMATCH')
    check_disk(document.disk_id)


def verify_root_document(document: Document):
    if (type(document) is not Document or document.id != TEST_ROOT_ID
            or document.is_folder is not True
            or document.path not in (None, '', ROOT_PATH)):
        raise ValidationError('TEST_SCOPE_ROOT_MISMATCH')
    check_disk(document.disk_id)


def verify_created_document(document: Document, identifier: int, *, require_path=True,
                            expected_filename=TEST_FILENAME, expected_path=TEST_PATH_IDS):
    if (type(document) is not Document or document.id != identifier
            or identifier in expected_path or document.is_folder is not False
            or document.name != expected_filename):
        raise ValidationError('TEST_DOCUMENT_MISMATCH')
    expected_path = '.'.join(map(str, (*expected_path, identifier)))
    if (require_path and document.path != expected_path
            or document.path not in (None, '', expected_path)):
        raise ValidationError('TEST_DOCUMENT_PATH_MISMATCH')
    check_disk(document.disk_id)
