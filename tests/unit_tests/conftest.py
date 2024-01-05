import copy
import json
from pathlib import Path

import pytest
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType


@pytest.fixture
def cbom():
    cbom = Bom()

    root_component = Component(
        bom_ref='root',
        name='springfield-nuclear-power-plant',
        type=ComponentType.APPLICATION
    )
    cbom.metadata.component = root_component
    return cbom


@pytest.fixture()
def aes():
    with open(Path(__file__).absolute().parent / 'data' / 'codeql' / 'aes.sarif') as data:
        data = json.load(data)
        return data


@pytest.fixture
def make_aes_component(aes):

    def _make_component(start_line, end_line):
        data = copy.deepcopy(aes)
        data['locations'][0]['physicalLocation']['region']['startLine'] = start_line
        data['locations'][0]['physicalLocation']['region']['endLine'] = end_line

        data['locations'][0]['physicalLocation']['contextRegion']['startLine'] = start_line - 2
        data['locations'][0]['physicalLocation']['contextRegion']['endLine'] = end_line + 2
        return data

    return _make_component


@pytest.fixture()
def dsa():
    with open(Path(__file__).absolute().parent / 'data' / 'codeql' / 'dsa.sarif') as data:
        data = json.load(data)
        return data


@pytest.fixture
def make_dsa_component(dsa):

    def _make_component(start_line, end_line):
        data = copy.deepcopy(dsa)
        data['locations'][0]['physicalLocation']['region']['startLine'] = start_line
        data['locations'][0]['physicalLocation']['region']['endLine'] = end_line

        data['locations'][0]['physicalLocation']['contextRegion']['startLine'] = start_line - 2
        data['locations'][0]['physicalLocation']['contextRegion']['endLine'] = end_line + 2
        return data

    return _make_component


@pytest.fixture()
def fernet():
    with open(Path(__file__).absolute().parent / 'data' / 'codeql' / 'fernet.sarif') as data:
        data = json.load(data)
        return data


@pytest.fixture()
def rsa():
    with open(Path(__file__).absolute().parent / 'data' / 'codeql' / 'rsa.sarif') as data:
        data = json.load(data)
        return data


@pytest.fixture
def make_rsa_component(rsa):

    def _make_component(start_line, end_line):
        data = copy.deepcopy(rsa)
        data['locations'][0]['physicalLocation']['region']['startLine'] = start_line
        data['locations'][0]['physicalLocation']['region']['endLine'] = end_line

        data['locations'][0]['physicalLocation']['contextRegion']['startLine'] = start_line - 2
        data['locations'][0]['physicalLocation']['contextRegion']['endLine'] = end_line + 2
        return data

    return _make_component
