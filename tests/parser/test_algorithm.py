from unittest.mock import patch

import pytest
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import Mode, Padding, Primitive

from cbom.parser import algorithm
from tests import utils

_CODE_SNIPPET_AES = '''
def encrypt(message):
    padder = padding.PKCS7(128).padder()
    message = padder.update(message.encode()) + padder.finalize()

    key = os.urandom(32)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.ECB(initialization_vector=os.urandom(16))
    ).encryptor()

    ciphertext = encryptor.update(message) + encryptor.finalize()
    return ciphertext
'''

_CODE_SNIPPET_RSA = '''
def encrypt(message: str):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    certificate = x509.CertificateBuilder().public_key(public_key)
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext
'''


def test_algorithm__should_infer_primitive():
    codeql_result = utils.load_data(code_snippet=_CODE_SNIPPET_AES)

    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.primitive == Primitive.BLOCK_CIPHER


def test_algorithm__should_extract_mode_for_block_cipher():
    codeql_result = utils.load_data(code_snippet=_CODE_SNIPPET_AES)

    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.mode == Mode.ECB


def test_algorithm__should_extract_padding():
    codeql_result = utils.load_data(code_snippet=_CODE_SNIPPET_AES)

    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.padding == Padding.PKCS7


def test_algorithm__should_extract_crypto_functions():
    codeql_result = utils.load_data(code_snippet=_CODE_SNIPPET_RSA)

    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.crypto_functions == {'generate', 'encrypt'}


def test_algorithm__should_not_identify_non_function_match_as_crypto_function():
    codeql_result = utils.load_data(code_snippet=_CODE_SNIPPET_RSA + 'def decrypt(): ...')

    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert 'decrypt' not in cbom.components[0].crypto_properties.algorithm_properties.crypto_functions


def test_algorithm__should_transform_fernet():
    code_snippet = '''
    def encrypt(message):
        encryptor = Fernet(Fernet.generate_key())
        ciphertext = encryptor.encrypt(message.encode())
        return ciphertext
    '''
    codeql_result = utils.load_data(code_snippet=code_snippet)

    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.variant == 'AES-128-CBC'


def test_algorithm__should_generate_certificate_component_for_pke(certificate_mock):
    codeql_result = utils.load_data(code_snippet=_CODE_SNIPPET_RSA)

    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result)

    certificate_mock.assert_called_once_with(cbom, codeql_result)


def test_algorithm__should_generate_private_key_component_for_pke(private_key_mock):
    codeql_result = utils.load_data(code_snippet=_CODE_SNIPPET_RSA)

    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result)

    private_key_mock.assert_called_once_with(cbom, codeql_result)


def test_algorithm__should_update_existing_component_with_overlapping_detection_context():
    codeql_result_1 = utils.load_data(code_snippet=_CODE_SNIPPET_AES, line_range=(10, 21))
    codeql_result_2 = utils.load_data(code_snippet=_CODE_SNIPPET_AES, line_range=(20, 31))

    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result_1)
    algorithm.parse_algorithm(cbom, codeql_result_2)

    assert len(cbom.components) == 1
    assert len(cbom.components[0].crypto_properties.detection_context) == 1


def test_algorithm__should_update_existing_component_with_new_detection_context():
    codeql_result_1 = utils.load_data(code_snippet=_CODE_SNIPPET_AES, line_range=(10, 21))
    codeql_result_2 = utils.load_data(code_snippet=_CODE_SNIPPET_AES, line_range=(50, 61))

    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result_1)
    algorithm.parse_algorithm(cbom, codeql_result_2)

    assert len(cbom.components) == 1
    assert len(cbom.components[0].crypto_properties.detection_context) == 2


def test_algorithm__should_not_update_existing_component_when_algorithms_are_different():
    codeql_result_1 = utils.load_data(code_snippet=_CODE_SNIPPET_AES, line_range=(10, 33))
    codeql_result_2 = utils.load_data(code_snippet=_CODE_SNIPPET_RSA, line_range=(20, 43))

    cbom = utils.generate_cbom_for_tests()
    algorithm.parse_algorithm(cbom, codeql_result_1)
    algorithm.parse_algorithm(cbom, codeql_result_2)

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
