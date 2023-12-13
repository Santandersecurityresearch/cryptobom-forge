from cbom.parser import related_crypto_material
from tests import utils


def test_related_crypto_material__should_extract_key_size_for_key():
    codeql_result = utils.load_data('rsa.sarif')

    cbom = utils.generate_cbom_for_tests()
    related_crypto_material.parse_private_key(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.related_crypto_material_properties.size == 2048


def test_related_crypto_material__should_update_existing_component_when_overlapping_detection_context():
    codeql_result_1 = utils.load_data('rsa.sarif')
    codeql_result_2 = utils.load_data('rsa.sarif')
    utils.edit_line_range_for_component(codeql_result_2, should_overlap=True)

    cbom = utils.generate_cbom_for_tests()
    related_crypto_material.parse_private_key(cbom, codeql_result_1)
    related_crypto_material.parse_private_key(cbom, codeql_result_2)

    assert len(cbom.components) == 1
    assert len(cbom.components[0].crypto_properties.detection_context) == 1
