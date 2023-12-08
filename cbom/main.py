import json
import re
from argparse import ArgumentParser
from pathlib import Path

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import AssetType
from cyclonedx.output.json import JsonV1Dot4CbomV1Dot0

from cbom.cryptocheck import cryptocheck
from cbom.parser import algorithm, metadata, utils

file_count = 0

cbom = Bom()
unregistered_dependencies = []


def start():
    parser = ArgumentParser()
    parser.add_argument('path', type=Path, help='Directory path or file path to parse')
    parser.add_argument('--application-name', '-an', help='Name of the root application for the CBOM')
    parser.add_argument('--exclude', '-e', help='Exclude CodeQL findings in files that match a regex')
    parser.add_argument('--cryptocheck', '-cc', action='store_true', default=False, help='Enable crypto vulnerability scanning')
    parser.add_argument('--rules-file', '-rf', type=Path, help='Use a custom ruleset for CryptoCheck analysis')
    parser.add_argument('--cbom-output-file', '-cbf', default='cbom.json', help='CBOM output file')
    parser.add_argument('--cryptocheck-output-file', '-ccf', default='cryptocheck.sarif', help='CryptoCheck analysis output file')
    args = parser.parse_args()

    exclusion_pattern = re.compile(args.exclude) if args.exclude else None
    if (path := args.path).is_file():
        _read_file(path, application_name=args.application_name, exclusion_pattern=exclusion_pattern)
        for unregistered_dependency in unregistered_dependencies:
            _link_dependency(unregistered_dependency)
    else:
        global file_count

        for file in [*list(path.glob('*.sarif')), *list(path.glob('*.json'))]:
            file_count += 1
            _read_file(file, application_name=args.application_name, exclusion_pattern=exclusion_pattern)
        for unregistered_dependency in unregistered_dependencies:
            _link_dependency(unregistered_dependency)  # must be done only after all components have been added to CBOM

    if args.cryptocheck:
        cryptocheck_output = cryptocheck.validate_cbom(cbom, args.rules_file)
        with open(args.cryptocheck_output_file, 'w') as output_file:
            json.dump(cryptocheck_output, output_file, indent=4, sort_keys=True)

    cbom_output = JsonV1Dot4CbomV1Dot0(cbom).output_as_string(bom_format='CBOM')
    with open(args.cbom_output_file, 'w') as output_file:
        json.dump(json.loads(cbom_output), output_file, indent=4)


def _read_file(query_file, application_name=None, exclusion_pattern=None):
    with open(query_file) as query_output:
        query_output = json.load(query_output)['runs'][0]

        for result in query_output['results']:
          snippet = result['locations'][0]['physicalLocation']['contextRegion']['snippet']['text']
          lineStart = result['locations'][0]['physicalLocation']['region']['startLine']
          snippetStart = result['locations'][0]['physicalLocation']['contextRegion']['startLine']

          # Check if '\r\n' is present in the snippet before splitting
          if '\r\n' in snippet:
            actualLine = ""
            array_of_lines = []
            # Split the code snippet at instances of '\r\n' and handle consecutive newlines
            array_of_lines = [line.strip() for line in snippet.split('\r\n')]
            actualLine = array_of_lines[lineStart - 1]

            # Update the snippet record in query_output
            result['locations'][0]['physicalLocation']['contextRegion']['snippet']['text'] = actualLine

        if file_count < 2:
            if application_name:
                cbom.metadata.component = Component(name=application_name, type=ComponentType.APPLICATION)
            elif version_control_details := query_output.get('versionControlProvenance'):
                root_component = metadata.get_root_component_info(version_control_details=version_control_details[0])
                cbom.metadata.component = root_component
            else:
                cbom.metadata.component = Component(name='root', type=ComponentType.APPLICATION)

            for tool in metadata.get_tool_info(tool_info=query_output['tool']):
                cbom.metadata.tools.add(tool)

        for result in query_output['results']:
            uri = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
            if not exclusion_pattern or not exclusion_pattern.fullmatch(uri):
                _parse_codeql_finding(result)


def _parse_codeql_finding(finding):
    component = algorithm.parse_algorithm(cbom, finding)

    if component:
        unregistered_dependencies.append(component)


def _link_dependency(dependency):
    context = dependency.crypto_properties.detection_context[0]

    for component in cbom.components:
        if component.crypto_properties.asset_type is AssetType.ALGORITHM:
            if utils.is_existing_detection_context_match(component, context):
                cbom.register_dependency(component, depends_on=[dependency])


if __name__ == '__main__':
    start()
