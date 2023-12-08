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


def load_data(path):
    with open(Path(__file__).absolute().parent / path) as data:
        return json.load(data)
