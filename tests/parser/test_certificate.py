from cbom.parser import certificate
from tests import utils


def test_certificate__should_generate_distinguished_name():
    codeql_result = utils.load_data('rsa.sarif')

    cbom = utils.generate_cbom_for_tests()
    certificate.parse_x509_certificate_details(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.certificate_properties.subject_name == 'C=US, L=Springfield, O=Springfield Nuclear Power Plant, CN=springfield-nuclear.com'


def test_certificate__should_extract_certificate_algorithm():
    codeql_result = utils.load_data('rsa.sarif')

    cbom = utils.generate_cbom_for_tests()
    certificate.parse_x509_certificate_details(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.certificate_properties.certificate_algorithm == 'RSA'


def test_certificate__should_extract_signature_algorithm():
    codeql_result = utils.load_data('rsa.sarif')

    cbom = utils.generate_cbom_for_tests()
    certificate.parse_x509_certificate_details(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.certificate_properties.certificate_signature_algorithm == 'SHA256'


def test_certificate__should_update_existing_component_when_overlapping_detection_context():
    codeql_result_1 = utils.load_data('rsa.sarif')
    codeql_result_2 = utils.load_data('rsa.sarif')
    utils.edit_line_range_for_component(codeql_result_2, should_overlap=True)

    cbom = utils.generate_cbom_for_tests()
    certificate.parse_x509_certificate_details(cbom, codeql_result_1)
    certificate.parse_x509_certificate_details(cbom, codeql_result_2)

    assert len(cbom.components) == 1
    assert len(cbom.components[0].crypto_properties.detection_context) == 1


def test_certificate__should_not_update_existing_component_when_certificate_algorithms_are_different():
    codeql_result_1 = utils.load_data('rsa.sarif')
    codeql_result_2 = utils.load_data('dsa.sarif')

    cbom = utils.generate_cbom_for_tests()
    certificate.parse_x509_certificate_details(cbom, codeql_result_1)
    certificate.parse_x509_certificate_details(cbom, codeql_result_2)

    assert len(cbom.components) == 2
