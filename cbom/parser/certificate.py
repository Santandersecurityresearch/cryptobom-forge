import re
import uuid

from cyclonedx.model.component import ComponentType, Component
from cyclonedx.model.crypto import CertificateProperties, CryptoProperties, AssetType

from cbom import lib_utils
from cbom.parser import utils

_X509_ATTRIBUTE_NAMES = {
    'COMMON_NAME': 'CN',  # 2.5.4.3
    'LOCALITY_NAME': 'L',  # 2.5.4.7
    'STATE_OR_PROVINCE_NAME': 'ST',  # 2.5.4.8
    'ORGANIZATION_NAME': 'O',  # 2.5.4.10
    'ORGANIZATIONAL_UNIT_NAME': 'OU',  # 2.5.4.11
    'COUNTRY_NAME': 'C',  # 2.5.4.6
    'DOMAIN_COMPONENT': 'DC',  # 0.9.2342.19200300.100.1.2
    'USER_ID': 'UID',  # 0.9.2342.19200300.100.1.1
}

_X509_ATTRIBUTES_REGEX = re.compile(f"({'|'.join(_X509_ATTRIBUTE_NAMES.keys())})(.*['\"].*['\"])", flags=re.IGNORECASE)
_SIGNING_ALGORITHM_REGEX = re.compile(f"sign[A-Z\\d_$]*\\(.*({'|'.join(lib_utils.get_algorithms())}).*\\)", flags=re.IGNORECASE)


def parse_x509_certificate_details(cbom, codeql_result):
    crypto_properties = _generate_crypto_component(codeql_result)
    unique_identifier = uuid.uuid4()

    component = Component(
        bom_ref=f'cryptography:certificate:{unique_identifier}',
        name=str(unique_identifier),
        type=ComponentType.CRYPTO_ASSET,
        crypto_properties=crypto_properties
    )
    if not (existing_component := _is_existing_component_overlap(cbom, component)):
        cbom.components.add(component)
    else:
        component = _update_existing_component(existing_component, component)
    return component


def _generate_crypto_component(codeql_result):
    code_snippet = codeql_result['locations'][0]['physicalLocation']['contextRegion']['snippet']['text']
    subject = issuer = _generate_distinguished_name(code_snippet)

    return CryptoProperties(
        asset_type=AssetType.CERTIFICATE,
        certificate_properties=CertificateProperties(
            subject_name=subject,
            issuer_name=issuer,
            certificate_algorithm=utils.get_algorithm(code_snippet),
            certificate_signature_algorithm=_extract_signature_algorithm(code_snippet),  # todo: dependency relation for signing algorithm
            certificate_format='X.509'
        ),
        detection_context=utils.get_detection_contexts(locations=codeql_result['locations'])
    )


def _generate_distinguished_name(code_snippet):

    def append(text):
        nonlocal distinguished_name
        distinguished_name += f', {text}' if distinguished_name else text

    distinguished_name = ''
    for attribute_name, attribute_value in re.findall(_X509_ATTRIBUTES_REGEX, code_snippet):
        start_index = attribute_value.index(attribute_value[-1])
        attribute_value = attribute_value[start_index + 1:len(attribute_value) - 1]
        append(f'{_X509_ATTRIBUTE_NAMES[attribute_name.upper()]}={attribute_value}')
    return distinguished_name


def _extract_signature_algorithm(code_snippet):
    match = _SIGNING_ALGORITHM_REGEX.search(code_snippet)
    if match:
        return _SIGNING_ALGORITHM_REGEX.sub('\\1', match.group())


def _is_existing_component_overlap(cbom, component):
    certificate_components = (c for c in cbom.components if c.crypto_properties.asset_type == AssetType.CERTIFICATE)

    for existing_component in certificate_components:
        if (  # same certificate algorithm & overlapping detection context
            existing_component.crypto_properties.certificate_properties.certificate_algorithm == component.crypto_properties.certificate_properties.certificate_algorithm and
            utils.is_existing_detection_context_match(existing_component, component.crypto_properties.detection_context[0])
        ):
            return existing_component


def _update_existing_component(existing_component, component):
    context = component.crypto_properties.detection_context[0]

    if existing_context := utils.is_existing_detection_context_match(existing_component, context):
        existing_context.additional_context = utils.merge_code_snippets(existing_context, context)
        existing_context.line_numbers = existing_context.line_numbers.union(context.line_numbers)

        for field in vars(component.crypto_properties.certificate_properties):
            if not getattr(existing_component.crypto_properties.certificate_properties, field):
                field_value = getattr(component.crypto_properties.certificate_properties, field)
                setattr(existing_component.crypto_properties.certificate_properties, field, field_value)
        return existing_component
