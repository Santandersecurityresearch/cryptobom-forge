from pathlib import Path

import yaml
from requests.structures import CaseInsensitiveDict

with open(Path(__file__).absolute().parent / 'resources/library.yml') as data:
    YAML_LIBRARY = yaml.safe_load(data)


def get_algorithms():
    return YAML_LIBRARY['crypto']['algorithms']


def get_block_modes():
    return YAML_LIBRARY['crypto']['block-modes']


def get_functions():
    return YAML_LIBRARY['crypto']['functions']


def get_key_lengths():
    return YAML_LIBRARY['crypto']['key-lengths']


def get_padding_schemes():
    return YAML_LIBRARY['crypto']['padding-schemes']


def get_primitive_mapping(algorithm):
    return CaseInsensitiveDict(YAML_LIBRARY['crypto']['primitive-mappings']).get(algorithm, 'unknown')


def get_query_mapping(rule_id):
    return CaseInsensitiveDict(YAML_LIBRARY['codeql']['query-mappings']).get(rule_id)
