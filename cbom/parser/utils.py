import re
from difflib import SequenceMatcher

from cyclonedx.model.crypto import DetectionContext

from cbom import lib_utils

_ALGORITHM_REGEX = re.compile(f"{'|'.join(lib_utils.get_algorithms())}", flags=re.IGNORECASE)
_KEY_LENGTH_REGEX = re.compile(f"\\D({'|'.join([str(l) for l in lib_utils.get_key_lengths()])})\\D")


def get_detection_contexts(locations):

    def parse_location(physical_location):
        file_path = physical_location['artifactLocation']['uri']

        # use line numbers from region if possible as they give exist location
        if region := physical_location.get('region'):
            start_line = region['startLine']
            end_line = region.get('endLine', start_line)  # Use start_line if endLine doesn't exist
            line_numbers = list(range(start_line, end_line + 1))
        else:
            line_numbers = []

        if context_region := physical_location.get('contextRegion'):
            if not line_numbers:
                line_numbers = list(range(context_region['startLine'], context_region['endLine'] + 1))
            code_snippet = context_region.get('snippet').get('text')
            return DetectionContext(file_path=file_path, line_numbers=line_numbers, additional_context=code_snippet)

    detection_contexts = [parse_location(location.get('physicalLocation')) for location in locations]
    return detection_contexts


def get_algorithm(code_snippet):
    match = _ALGORITHM_REGEX.search(code_snippet)
    if match:
        return match.group()
    return 'unknown'


def get_key_size(code_snippet):
    match = _KEY_LENGTH_REGEX.search(code_snippet)
    if match:
        return _KEY_LENGTH_REGEX.sub('\\1', match.group())


def is_existing_detection_context_match(component, new_context):
    for context in component.crypto_properties.detection_context:
        if context.file_path == new_context.file_path and context.line_numbers.intersection(new_context.line_numbers):
            return context


def merge_code_snippets(dc1, dc2):
    first = (dc1 if min(dc1.line_numbers) < min(dc2.line_numbers) else dc2).additional_context
    second = (dc1 if max(dc1.line_numbers) > max(dc2.line_numbers) else dc2).additional_context

    match = SequenceMatcher(None, first, second).find_longest_match()
    return f'{first[:match.a]}{second[:match.size]}{second[match.size:]}'
