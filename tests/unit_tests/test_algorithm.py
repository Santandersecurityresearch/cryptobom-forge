from unittest.mock import patch

import pytest
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import Mode, Padding, Primitive

from cbom.parser import algorithm


def test_algorithm__should_infer_primitive(cbom, aes):
    algorithm.parse_algorithm(cbom, aes)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.primitive == Primitive.BLOCK_CIPHER


def test_algorithm__should_extract_block_mode(cbom, aes):
    algorithm.parse_algorithm(cbom, aes)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.mode == Mode.ECB


def test_algorithm__should_extract_padding(cbom, aes):
    algorithm.parse_algorithm(cbom, aes)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.padding == Padding.PKCS7


def test_algorithm__should_extract_crypto_functions(cbom, rsa):
    algorithm.parse_algorithm(cbom, rsa)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.crypto_functions == {'generate', 'encrypt', 'sign'}


def test_algorithm__should_not_identify_non_function_match_as_crypto_function(cbom, rsa):
    rsa['contextRegion']['snippet']['text'] += '\n\ndef decrypt(): ...'

    algorithm.parse_algorithm(cbom, rsa)

    assert len(cbom.components) == 1
    assert 'decrypt' not in cbom.components[0].crypto_properties.algorithm_properties.crypto_functions


def test_algorithm__should_transform_fernet(cbom, fernet):
    algorithm.parse_algorithm(cbom, fernet)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.variant == 'AES-128-CBC'


def test_algorithm__public_key_encryption__should_generate_certificate_component(cbom, rsa, certificate_mock):
    algorithm.parse_algorithm(cbom, rsa)

    certificate_mock.assert_called_once_with(cbom, rsa)


def test_algorithm__public_key_encryption__should_generate_private_key_component(cbom, rsa, private_key_mock):
    algorithm.parse_algorithm(cbom, rsa)

    private_key_mock.assert_called_once_with(cbom, rsa)


def test_algorithm__same_algorithm_with_overlapping_detection_contexts__should_update_existing_detection_context(cbom, make_aes_component):
    aes1 = make_aes_component(start_line=10, end_line=20)
    aes2 = make_aes_component(start_line=15, end_line=25)

    algorithm.parse_algorithm(cbom, aes1)
    algorithm.parse_algorithm(cbom, aes2)

    assert len(cbom.components) == 1
    assert len(cbom.components[0].crypto_properties.detection_context) == 1


def test_algorithm__same_algorithm_with_non_overlapping_detection_contexts__should_update_existing_component_with_new_detection_context(cbom, make_aes_component):
    aes1 = make_aes_component(start_line=10, end_line=20)
    aes2 = make_aes_component(start_line=50, end_line=60)

    algorithm.parse_algorithm(cbom, aes1)
    algorithm.parse_algorithm(cbom, aes2)

    assert len(cbom.components) == 1
    assert len(cbom.components[0].crypto_properties.detection_context) == 2


def test_algorithm__different_algorithms_with_overlapping_detection_contexts__should_not_update_existing_component(cbom, make_aes_component, make_rsa_component):
    aes = make_aes_component(start_line=10, end_line=20)
    rsa = make_rsa_component(start_line=10, end_line=20)

    algorithm.parse_algorithm(cbom, aes)
    algorithm.parse_algorithm(cbom, rsa)

    assert len(cbom.components) == 2


@pytest.fixture(autouse=True)
def certificate_mock():
    with patch.object(algorithm.certificate, 'parse_x509_certificate_details') as mock:
        mock.return_value = Component(name='certificate-component', type=ComponentType.CRYPTO_ASSET)
        yield mock


@pytest.fixture(autouse=True)
def private_key_mock():
    with patch.object(algorithm.related_crypto_material, 'parse_private_key') as mock:
        mock.return_value = Component(name='private-key-component', type=ComponentType.CRYPTO_ASSET)
        yield mock
