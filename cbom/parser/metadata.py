from cyclonedx.model import Tool, ExternalReference, ExternalReferenceType, XsUri
from cyclonedx.model.component import Component, ComponentType


def get_root_component_info(version_control_details):
    path = version_control_details['repositoryUri'].split('https://github.com/')[1]
    external_reference = ExternalReference(url=version_control_details['repositoryUri'], type=ExternalReferenceType.SCM)

    return Component(
        bom_ref=path,
        name=path.split('/')[-1],
        type=ComponentType.APPLICATION,
        external_references=[external_reference]
    )


def get_tool_info(tool_info):

    def parse_tool_component(tool_component):
        name = tool_component['name']
        vendor = tool_component.get('organization')
        version = tool_component.get('semanticVersion', tool_component.get('version'))

        external_references = []
        if download_url := tool_component.get('downloadUri'):
            reference = ExternalReference(url=XsUri(download_url), type=ExternalReferenceType.DISTRIBUTION)
            external_references.append(reference)
        if information_url := tool_component.get('informationUri'):
            reference = ExternalReference(url=XsUri(information_url), type=ExternalReferenceType.DOCUMENTATION)
            external_references.append(reference)
        return Tool(vendor=vendor, name=name, version=version, external_references=external_references)

    tools = [parse_tool_component(tool_info['driver'])]
    for extension in tool_info.get('extensions', []):
        tools.append(parse_tool_component(extension))

    return tools
