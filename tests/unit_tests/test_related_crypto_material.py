from cbom.parser import related_crypto_material


def test_private_key__should_extract_key_size_for_key(cbom, rsa):
    related_crypto_material.parse_private_key(cbom, rsa)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.related_crypto_material_properties.size == 2048


def test_private_key__overlapping_detection_contexts__should_update_existing_detection_context(cbom, make_rsa_component):
    rsa1 = make_rsa_component(start_line=10, end_line=20)
    rsa2 = make_rsa_component(start_line=15, end_line=25)

    related_crypto_material.parse_private_key(cbom, rsa1)
    related_crypto_material.parse_private_key(cbom, rsa2)

    assert len(cbom.components) == 1
    assert len(cbom.components[0].crypto_properties.detection_context) == 1
