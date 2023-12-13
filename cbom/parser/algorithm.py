import re
import uuid

from cyclonedx.model.component import ComponentType, Component
from cyclonedx.model.crypto import Primitive, CryptoProperties, AssetType, AlgorithmProperties, Mode, Padding

from cbom import lib_utils
from cbom.parser import certificate, utils, related_crypto_material

_BLOCK_MODE_REGEX = re.compile(f"{'|'.join(lib_utils.get_block_modes())}", flags=re.IGNORECASE)
_FUNCTION_REGEX = re.compile(f"\\.[A-Z_\\d]*({'|'.join(lib_utils.get_functions())})[A-Z_\\d]*")
_PADDING_REGEX = re.compile(f"{'|'.join(lib_utils.get_padding_schemes())}", flags=re.IGNORECASE)


def parse_algorithm(cbom, codeql_result):
    crypto_properties = _generate_crypto_component(codeql_result)
    if (padding := crypto_properties.algorithm_properties.padding) not in [Padding.OTHER, Padding.UNKNOWN]:
        name = f'{crypto_properties.algorithm_properties.variant}-{padding.value.upper()}'
    else:
        name = crypto_properties.algorithm_properties.variant

    algorithm_component = Component(
        bom_ref=f'cryptography:algorithm:{uuid.uuid4()}',
        name=name,
        type=ComponentType.CRYPTO_ASSET,
        crypto_properties=crypto_properties
    )

    if not (existing_component := _is_existing_component_overlap(cbom, algorithm_component)):
        cbom.components.add(algorithm_component)
        cbom.register_dependency(cbom.metadata.component, depends_on=[algorithm_component])
    else:
        algorithm_component = _update_existing_component(existing_component, algorithm_component)

    if crypto_properties.algorithm_properties.primitive == Primitive.PUBLIC_KEY_ENCRYPTION:
        code_snippet = codeql_result['locations'][0]['physicalLocation']['contextRegion']['snippet']['text']
        if 'key' in code_snippet.lower():
            private_key_component = related_crypto_material.parse_private_key(cbom, codeql_result)
            cbom.register_dependency(algorithm_component, depends_on=[private_key_component])

        if 'x509' in code_snippet.lower() or 'x.509' in code_snippet.lower():
            certificate_component = certificate.parse_x509_certificate_details(cbom, codeql_result)
            cbom.register_dependency(algorithm_component, depends_on=[certificate_component])


def _generate_crypto_component(codeql_result):
    algorithm = utils.get_algorithm(utils.extract_precise_snippet(codeql_result['locations'][0]['physicalLocation']['contextRegion']['snippet']['text'], codeql_result['locations'][0]['physicalLocation']['region']))

    code_snippet = codeql_result['locations'][0]['physicalLocation']['contextRegion']['snippet']['text']

    if algorithm.lower() == 'fernet':
        algorithm, key_size, mode = 'AES', '128', Mode.CBC
        primitive = Primitive.BLOCK_CIPHER
    else:
        primitive = _infer_primitive(algorithm)
        if 'key' in code_snippet.lower() and primitive != Primitive.HASH:
            key_size = utils.get_key_size(code_snippet)
        else:
            key_size = None

        try:
            if primitive == Primitive.BLOCK_CIPHER:
                mode = _extract_mode(code_snippet)
                mode = Mode(mode.lower()) if mode else Mode.UNKNOWN
            else:
                mode = None
        except ValueError:
            mode = Mode.OTHER

    try:
        padding = _extract_padding(code_snippet)
        padding = Padding(padding.lower()) if padding else Padding.UNKNOWN
    except ValueError:
        padding = Padding.OTHER

    return CryptoProperties(
        asset_type=AssetType.ALGORITHM,
        algorithm_properties=AlgorithmProperties(
            primitive=primitive,
            variant=_build_variant(algorithm, key_size=key_size, block_mode=mode),
            mode=mode,
            padding=padding,
            crypto_functions=_extract_crypto_functions(codeql_result['locations'][0]['physicalLocation']['contextRegion']['snippet']['text'])
        ),
        detection_context=utils.get_detection_contexts(locations=codeql_result['locations'])
    )


def _build_variant(algorithm, *, key_size=None, block_mode=None):
    variant = algorithm.upper()
    if key_size:
        variant += f'-{key_size}'
    if block_mode and block_mode not in [Mode.OTHER, Mode.UNKNOWN]:
        variant += f'-{block_mode.value.upper()}'
    return variant


def _extract_crypto_functions(code_snippet):
    matches = _FUNCTION_REGEX.findall(''.join(code_snippet.split()))
    matches = [_FUNCTION_REGEX.sub('\\1', m) for m in matches]
    return set(matches)


def _extract_mode(code_snippet):
    match = _BLOCK_MODE_REGEX.search(code_snippet)
    if match:
        return match.group()


def _extract_padding(code_snippet):
    match = _PADDING_REGEX.search(code_snippet)
    if match:
        return match.group()


def _infer_primitive(algorithm, additional_context=None):
    primitive = lib_utils.get_primitive_mapping(algorithm.lower())
    return Primitive(primitive)


def _is_existing_component_overlap(cbom, component):
    algorithm_components = (c for c in cbom.components if c.crypto_properties.asset_type == AssetType.ALGORITHM)

    for existing_component in algorithm_components:
        if existing_component.name == component.name:
            return existing_component


def _update_existing_component(existing_component, component):
    new_context = component.crypto_properties.detection_context[0]

    if existing_context := utils.is_existing_detection_context_match(existing_component, new_context):
        existing_context.additional_context = utils.merge_code_snippets(existing_context, new_context)
        existing_context.line_numbers = existing_context.line_numbers.union(new_context.line_numbers)
        return existing_component
    else:
        existing_component.crypto_properties.algorithm_properties.crypto_functions.update(component.crypto_properties.algorithm_properties.crypto_functions)
        existing_component.crypto_properties.detection_context.add(new_context)
        return existing_component
