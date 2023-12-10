from cbom.parser import utils
from cyclonedx.model.crypto import DetectionContext


def test_merge_code_snippets__should_handle_partially_overlapping_contexts():
    code_snippet_1 = '''
    def encrypt(message):
        key = os.urandom(32)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(initialization_vector=os.urandom(16))
    '''

    code_snippet_2 = '''
        encryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(initialization_vector=os.urandom(16))
        ).encryptor()
    
        ciphertext = encryptor.update(message) + encryptor.finalize()
        return ciphertext
    '''

    expected_code_snippet = '''
    def encrypt(message):
        key = os.urandom(32)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(initialization_vector=os.urandom(16))
        ).encryptor()
    
        ciphertext = encryptor.update(message) + encryptor.finalize()
        return ciphertext
    '''

    dc1 = DetectionContext(line_numbers=[10, 11, 12, 13, 14], additional_context=code_snippet_1)
    dc2 = DetectionContext(line_numbers=[12, 13, 14, 15, 16, 17, 18], additional_context=code_snippet_2)

    assert utils.merge_code_snippets(dc1, dc2) == expected_code_snippet


def test_merge_code_snippets__should_handle_wholly_overlapping_contexts():
    code_snippet_1 = '''
    def encrypt(message):
        key = os.urandom(32)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(initialization_vector=os.urandom(16))
        ).encryptor()

        ciphertext = encryptor.update(message) + encryptor.finalize()
        return ciphertext
    '''

    code_snippet_2 = '''
        encryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(initialization_vector=os.urandom(16))
        ).encryptor()
    '''

    dc1 = DetectionContext(line_numbers=[10, 11, 12, 13, 14, 15, 16, 17, 18], additional_context=code_snippet_1)
    dc2 = DetectionContext(line_numbers=[12, 13, 14, 15], additional_context=code_snippet_2)

    assert utils.merge_code_snippets(dc1, dc2) == code_snippet_1
