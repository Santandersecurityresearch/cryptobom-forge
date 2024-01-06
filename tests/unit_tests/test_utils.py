from cyclonedx.model.crypto import DetectionContext

from cbom.parser import utils

_CODE_SNIPPET = '''
def encrypt(message):
    key = os.urandom(32)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.ECB(initialization_vector=os.urandom(16))
    ).encryptor()

    ciphertext = encryptor.update(message) + encryptor.finalize()
    return ciphertext
'''


def test_get_algorithm__should_return_full_name_when_matched_algorithm_is_aliased():
    code_snippet = 'parameters = dh.generate_parameters(generator=2, key_size=2048)'
    algorithm = utils.get_algorithm(code_snippet)

    assert algorithm == 'DIFFIEHELLMAN'


def test_extract_precise_snippet__should_extract_line():
    region = {
        'startLine': 10,
        'endColumn': 25
    }
    expected = '    key = os.urandom(32)'

    assert utils.extract_precise_snippet(_CODE_SNIPPET, region) == expected


def test_extract_precise_snippet__should_handle_column_start_index():
    region = {
        'startLine': 3,
        'startColumn': 5,
        'endColumn': 25
    }
    expected = 'key = os.urandom(32)'

    assert utils.extract_precise_snippet(_CODE_SNIPPET, region) == expected


def test_extract_precise_snippet__should_handle_start_of_file_region():
    region = {
        'startLine': 2,
        'endColumn': 22
    }
    expected = 'def encrypt(message):'

    assert utils.extract_precise_snippet(_CODE_SNIPPET, region) == expected


def test_extract_precise_snippet__should_handle_multiline_region():
    region = {
        'startLine': 10,
        'startColumn': 5,
        'endLine': 12,
        'endColumn': 27
    }
    expected = 'key = os.urandom(32)\n    encryptor = Cipher(\n        algorithms.AES(key)'

    assert utils.extract_precise_snippet(_CODE_SNIPPET, region) == expected


def test_merge_code_snippets__should_handle_partially_overlapping_contexts():
    partial_code_snippet_1 = '\n'.join(_CODE_SNIPPET.split('\n')[:5])
    partial_code_snippet_2 = '\n'.join(_CODE_SNIPPET.split('\n')[2:])

    dc1 = DetectionContext(line_numbers=[10, 11, 12, 13, 14], additional_context=partial_code_snippet_1)
    dc2 = DetectionContext(line_numbers=[12, 13, 14, 15, 16, 17, 18], additional_context=partial_code_snippet_2)

    assert utils.merge_code_snippets(dc1, dc2) == _CODE_SNIPPET


def test_merge_code_snippets__should_handle_wholly_overlapping_contexts():
    partial_code_snippet = '\n'.join(_CODE_SNIPPET.split('\n')[2:5])

    dc1 = DetectionContext(line_numbers=[10, 11, 12, 13, 14, 15, 16, 17, 18], additional_context=_CODE_SNIPPET)
    dc2 = DetectionContext(line_numbers=[12, 13, 14, 15], additional_context=partial_code_snippet)

    assert utils.merge_code_snippets(dc1, dc2) == _CODE_SNIPPET
