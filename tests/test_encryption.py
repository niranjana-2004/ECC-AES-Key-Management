
import sys
import unittest
from pathlib import Path

# Add the project root to Python's import path.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.aes_encryption import (
    generate_aes_key,
    encrypt_data,
    decrypt_data,
)


class TestAESEncryption(unittest.TestCase):

    def test_encrypt_decrypt(self):
        original = b"This is a test file for my research project."

        key = generate_aes_key()
        ciphertext, nonce = encrypt_data(original, key)
        recovered = decrypt_data(ciphertext, key, nonce)

        self.assertNotEqual(ciphertext, original)
        self.assertEqual(recovered, original)

    def test_wrong_key_fails(self):
        original = b"Confidential research data."

        key = generate_aes_key()
        wrong_key = generate_aes_key()

        ciphertext, nonce = encrypt_data(original, key)

        with self.assertRaises(Exception):
            decrypt_data(ciphertext, wrong_key, nonce)


if __name__ == "__main__":
    unittest.main()
