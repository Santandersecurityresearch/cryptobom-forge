from cyclonedx.model.crypto import Mode, Padding, AssetType

from cbom.parser import algorithm
from tests import utils


def test_algorithm__should_extract_mode_for_block_cipher():
    codeql_result = utils.load_data('data/codeql/aes.sarif')
    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.mode == Mode.ECB


def test_algorithm__should_extract_padding():
    codeql_result = utils.load_data('data/codeql/aes.sarif')
    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.padding == Padding.PKCS7


def test_algorithm__should_transform_fernet():
    codeql_result = utils.load_data('data/codeql/fernet.sarif')
    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.variant == 'AES-128-CBC'


def test_algorithm__should_generate_certificate_component_for_pke():
    codeql_result = utils.load_data('data/codeql/rsa.sarif')
    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result)

    assert any(c.crypto_properties.asset_type == AssetType.CERTIFICATE for c in cbom.components)


def test_algorithm__should_generate_private_key_component_for_pke():
    codeql_result = utils.load_data('data/codeql/rsa.sarif')
    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result)

    assert any(
        c.crypto_properties.asset_type == AssetType.RELATED_CRYPTO_MATERIAL and
        c.crypto_properties.related_crypto_material_properties.related_crypto_material_type == 'privateKey' for
        c in cbom.components
    )
