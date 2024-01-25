from cbom.parser import certificate


def test_certificate__should_generate_distinguished_name(cbom, rsa):
    certificate.parse_x509_certificate_details(cbom, rsa)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.certificate_properties.subject_name == 'C=US, L=Springfield, O=Springfield Nuclear Power Plant, CN=springfield-nuclear.com'


def test_certificate__should_extract_certificate_algorithm(cbom, rsa):
    certificate.parse_x509_certificate_details(cbom, rsa)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.certificate_properties.certificate_algorithm == 'RSA'


def test_certificate__should_extract_signature_algorithm(cbom, rsa):
    certificate.parse_x509_certificate_details(cbom, rsa)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.certificate_properties.certificate_signature_algorithm == 'SHA256'


def test_certificate__same_algorithm_with_overlapping_detection_contexts__should_update_existing_detection_context(cbom, make_rsa_component):
    rsa1 = make_rsa_component(start_line=10, end_line=20)
    rsa2 = make_rsa_component(start_line=15, end_line=25)

    certificate.parse_x509_certificate_details(cbom, rsa1)
    certificate.parse_x509_certificate_details(cbom, rsa2)

    assert len(cbom.components) == 1
    assert len(cbom.components[0].crypto_properties.detection_context) == 1


def test_certificate__different_algorithms_with_overlapping_detection_contexts__should_not_update_existing_component(cbom, make_rsa_component, make_dsa_component):
    rsa = make_rsa_component(start_line=10, end_line=20)
    dsa = make_dsa_component(start_line=10, end_line=20)

    certificate.parse_x509_certificate_details(cbom, rsa)
    certificate.parse_x509_certificate_details(cbom, dsa)

    assert len(cbom.components) == 2
