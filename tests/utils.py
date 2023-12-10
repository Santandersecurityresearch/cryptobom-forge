import json
from pathlib import Path

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType


def generate_cbom_for_tests():
    cbom = Bom()

    root_component = Component(
        bom_ref='root',
        name='springfield-nuclear-power-plant',
        type=ComponentType.APPLICATION
    )
    cbom.metadata.component = root_component
    return cbom


def load_data(code_snippet, line_range=None):
    with open(Path(__file__).absolute().parent / 'data' / 'codeql' / 'algorithm.sarif') as data:
        data = json.load(data)
        data['locations'][0]['physicalLocation']['contextRegion']['snippet']['text'] = code_snippet

        if line_range:
            data['locations'][0]['physicalLocation']['contextRegion']['startLine'] = line_range[0]
            data['locations'][0]['physicalLocation']['contextRegion']['endLine'] = line_range[1]
        return data
