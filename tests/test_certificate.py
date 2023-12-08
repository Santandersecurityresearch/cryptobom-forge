from cbom.parser import certificate
from tests import utils


def test_certificate__should_generate_distinguished_name():
    codeql_result = utils.load_data('data/codeql/rsa.sarif')
    cbom = utils.generate_cbom_for_tests()
    certificate.parse_x509_certificate_details(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.certificate_properties.subject_name == 'O=Springfield Nuclear Power Plant, L=Springfield, C=United States of America'


def test_certificate__should_extract_signature_algorithm():
    codeql_result = utils.load_data('data/codeql/rsa.sarif')
    cbom = utils.generate_cbom_for_tests()
    certificate.parse_x509_certificate_details(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.certificate_properties.certificate_signature_algorithm == 'SHA256'
