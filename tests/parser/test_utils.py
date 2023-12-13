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
