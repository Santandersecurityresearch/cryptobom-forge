import json
from pathlib import Path

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType


def edit_line_range_for_component(codeql_result, should_overlap=False):
    location = codeql_result['locations'][0]['physicalLocation']
    line_span = location['region']['endLine'] - location['region']['startLine']

    if should_overlap:
        location['region']['startLine'] = location['region']['endLine'] - 1
        location['region']['endLine'] = location['region']['endLine'] + line_span - 1
    else:
        location['region']['startLine'] = location['region']['endLine'] + 5
        location['region']['endLine'] = location['region']['endLine'] + line_span + 5

    location['contextRegion']['startLine'] = location['region']['startLine'] - 2
    location['contextRegion']['endLine'] = location['region']['endLine'] + 2


def generate_cbom_for_tests():
    cbom = Bom()

    root_component = Component(
        bom_ref='root',
        name='springfield-nuclear-power-plant',
        type=ComponentType.APPLICATION
    )
    cbom.metadata.component = root_component
    return cbom


def load_data(file):
    with open(Path(__file__).absolute().parent / 'data' / 'codeql' / file) as data:
        data = json.load(data)
        return data
