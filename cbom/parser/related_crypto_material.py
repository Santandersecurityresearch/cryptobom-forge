import uuid

from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import CryptoProperties, AssetType, RelatedCryptoMaterialProperties, \
    RelatedCryptoMaterialType

from cbom.parser import utils


def parse_initialization_vector(cbom, finding):
    crypto_properties = _generate_crypto_component(finding, RelatedCryptoMaterialType.INITIALIZATION_VECTOR)
    unique_identifier = uuid.uuid4()

    component = Component(
        bom_ref=f'cryptography:iv:{unique_identifier}',
        name=str(unique_identifier),
        type=ComponentType.CRYPTO_ASSET,
        crypto_properties=crypto_properties
    )
    cbom.components.add(component)
    return component


def parse_private_key(cbom, finding):
    key_size = utils.get_key_size(finding['contextRegion']['snippet']['text'])
    if key_size:
        key_size = int(key_size)

    crypto_properties = _generate_crypto_component(finding, RelatedCryptoMaterialType.PRIVATE_KEY, size=key_size)
    unique_identifier = uuid.uuid4()

    component = Component(
        bom_ref=f'cryptography:private_key:{unique_identifier}',
        name=str(unique_identifier),
        type=ComponentType.CRYPTO_ASSET,
        crypto_properties=crypto_properties
    )
    if not (existing_component := _is_existing_component_overlap(cbom, component)):
        cbom.components.add(component)
    else:
        component = _update_existing_component(existing_component, component)
    return component


def _generate_crypto_component(component, material_type, *, size=None):
    return CryptoProperties(
        asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
        related_crypto_material_properties=RelatedCryptoMaterialProperties(
            related_crypto_material_type=material_type,
            size=size
        ),
        detection_context=[utils.get_detection_context(component)]
    )


def _is_existing_component_overlap(cbom, component):
    related_crypto_material_components = (c for c in cbom.components if c.crypto_properties.asset_type == AssetType.RELATED_CRYPTO_MATERIAL)

    for existing_component in related_crypto_material_components:
        if utils.is_existing_detection_context_match(existing_component, component.crypto_properties.detection_context[0]):
            return existing_component


def _update_existing_component(existing_component, component):
    context = component.crypto_properties.detection_context[0]

    if existing_context := utils.is_existing_detection_context_match(existing_component, context):
        existing_context.additional_context = utils.merge_code_snippets(existing_context, context)
        existing_context.line_numbers = existing_context.line_numbers.union(context.line_numbers)

        for field in vars(component.crypto_properties.related_crypto_material_properties):
            if not getattr(existing_component.crypto_properties.related_crypto_material_properties, field):
                field_value = getattr(component.crypto_properties.related_crypto_material_properties, field)
                setattr(existing_component.crypto_properties.related_crypto_material_properties, field, field_value)
        return existing_component
