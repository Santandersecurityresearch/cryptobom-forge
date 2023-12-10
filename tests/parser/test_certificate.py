from cbom.parser import certificate
from tests import utils

_CODE_SNIPPET = '''
def create_self_signed_certificate():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US')
        x509.NameAttribute(NameOID.LOCALITY_NAME, 'Springfield'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Springfield Nuclear Power Plant'),
        x509.NameAttribute(NameOID.COMMON_NAME, "springfield-nuclear.com")
    ])

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
    ).sign(key, hashes.SHA256())
    return certificate
'''


def test_certificate__should_generate_distinguished_name():
    codeql_result = utils.load_data(code_snippet=_CODE_SNIPPET)

    cbom = utils.generate_cbom_for_tests()
    certificate.parse_x509_certificate_details(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.certificate_properties.subject_name == 'C=US, L=Springfield, O=Springfield Nuclear Power Plant, CN=springfield-nuclear.com'


def test_certificate__should_extract_certificate_algorithm():
    codeql_result = utils.load_data(code_snippet=_CODE_SNIPPET)

    cbom = utils.generate_cbom_for_tests()
    certificate.parse_x509_certificate_details(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.certificate_properties.certificate_algorithm == 'RSA'


def test_certificate__should_extract_signature_algorithm():
    codeql_result = utils.load_data(code_snippet=_CODE_SNIPPET)

    cbom = utils.generate_cbom_for_tests()
    certificate.parse_x509_certificate_details(cbom, codeql_result)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.certificate_properties.certificate_signature_algorithm == 'SHA256'


def test_certificate__should_update_existing_component_when_overlapping_detection_context():
    codeql_result_1 = utils.load_data(code_snippet=_CODE_SNIPPET, line_range=(10, 33))
    codeql_result_2 = utils.load_data(code_snippet=_CODE_SNIPPET, line_range=(20, 43))

    cbom = utils.generate_cbom_for_tests()
    certificate.parse_x509_certificate_details(cbom, codeql_result_1)
    certificate.parse_x509_certificate_details(cbom, codeql_result_2)

    assert len(cbom.components) == 1
    assert len(cbom.components[0].crypto_properties.detection_context) == 1


def test_certificate__should_not_update_existing_component_when_certificate_algorithms_are_different():
    codeql_result_1 = utils.load_data(code_snippet=_CODE_SNIPPET, line_range=(10, 33))
    codeql_result_2 = utils.load_data(code_snippet=_CODE_SNIPPET.replace('rsa', 'dsa'), line_range=(20, 43))

    cbom = utils.generate_cbom_for_tests()
    certificate.parse_x509_certificate_details(cbom, codeql_result_1)
    certificate.parse_x509_certificate_details(cbom, codeql_result_2)

    assert len(cbom.components) == 2
