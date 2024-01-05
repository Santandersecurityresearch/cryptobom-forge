import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from cbom.cli import cli


def test_generate_cbom__should_generate_full_cbom(cbom_expected_full):
    path = Path(__file__).parent / 'data' / 'codeql' / 'full.sarif'

    response = CliRunner().invoke(cli.cryptobom, ['generate', str(path)])
    cbom = json.loads(response.output)

    assert len(cbom['components']) == len(cbom_expected_full['components'])


def test_generate_cbom__should_handle_directory(cbom_expected_full):
    path = Path(__file__).parent / 'data' / 'codeql' / 'partial_results'

    response = CliRunner().invoke(cli.cryptobom, ['generate', str(path)])
    cbom = json.loads(response.output)

    assert len(cbom['components']) == len(cbom_expected_full['components'])


def test_generate_cbom__should_generate_root_component():
    path = Path(__file__).parent / 'data' / 'codeql' / 'full.sarif'

    response = CliRunner().invoke(cli.cryptobom, ['generate', str(path), '-n', 'core-reactor'])
    cbom = json.loads(response.output)

    assert cbom['metadata']['component']


def test_generate_cbom__should_set_root_component_name():
    path = Path(__file__).parent / 'data' / 'codeql' / 'full.sarif'

    response = CliRunner().invoke(cli.cryptobom, ['generate', str(path), '-n', 'core-reactor'])
    cbom = json.loads(response.output)

    assert cbom['metadata']['component']['name'] == 'core-reactor'


def test_generate_cbom__should_exclude_finding_when_exclusion_pattern_match(cbom_expected_exclusion_pattern):
    path = Path(__file__).parent / 'data' / 'codeql' / 'full.sarif'

    response = CliRunner().invoke(cli.cryptobom, ['generate', str(path), '-e', '(.*/)?test(s)?.*'])
    cbom = json.loads(response.output)

    assert len(cbom['components']) == len(cbom_expected_exclusion_pattern['components'])


def test_generate_cbom__should_write_to_file(cbom_expected_full):
    path = Path(__file__).parent / 'data' / 'codeql' / 'full.sarif'

    output_file = tempfile.NamedTemporaryFile()
    CliRunner().invoke(cli.cryptobom, ['generate', str(path), '--output-file', output_file.name])

    with open(output_file.name, 'r') as tmp:
        cbom = json.load(tmp)
        assert len(cbom['components']) == len(cbom_expected_full['components'])


@pytest.fixture
def cbom_expected_full():
    with open(Path(__file__).parent / 'data' / 'cbom' / 'cbom_full.json') as cbom:
        return json.load(cbom)


@pytest.fixture
def cbom_expected_exclusion_pattern():
    with open(Path(__file__).parent / 'data' / 'cbom' / 'cbom_exclusion_pattern.json') as cbom:
        return json.load(cbom)
