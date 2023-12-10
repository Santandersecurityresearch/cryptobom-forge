from cbom.parser import related_crypto_material
from tests import utils

_CODE_SNIPPET_PRIVATE_KEY = '''
def get_key(message):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
'''


def test_related_crypto_material__should_extract_key_size_for_key():
    codeql_result = utils.load_data(code_snippet=_CODE_SNIPPET_PRIVATE_KEY)

    cbom = utils.generate_cbom_for_tests()
    related_crypto_material.parse_private_key(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.related_crypto_material_properties.size == 2048


def test_related_crypto_material__should_update_existing_component_when_overlapping_detection_context():
    codeql_result_1 = utils.load_data(code_snippet=_CODE_SNIPPET_PRIVATE_KEY, line_range=(10, 14))
    codeql_result_2 = utils.load_data(code_snippet=_CODE_SNIPPET_PRIVATE_KEY, line_range=(12, 16))

    cbom = utils.generate_cbom_for_tests()
    related_crypto_material.parse_private_key(cbom, codeql_result_1)
    related_crypto_material.parse_private_key(cbom, codeql_result_2)

    assert len(cbom.components) == 1
    assert len(cbom.components[0].crypto_properties.detection_context) == 1
