
import sys
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidTag

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.aes_encryption import generate_aes_key
from src.ecc_key_protection import (
    generate_ecc_key_pair,
    protect_aes_key,
    recover_aes_key,
)


class TestECCKeyProtection(unittest.TestCase):

    def test_protect_and_recover_aes_key(self):
        recipient_private, recipient_public = generate_ecc_key_pair()
        original_aes_key = generate_aes_key()

        protected = protect_aes_key(
            original_aes_key, recipient_public
        )

        recovered_aes_key = recover_aes_key(
            protected, recipient_private
        )

        self.assertEqual(recovered_aes_key, original_aes_key)

    def test_wrong_private_key_fails(self):
        _, recipient_public = generate_ecc_key_pair()
        wrong_private, _ = generate_ecc_key_pair()
        original_aes_key = generate_aes_key()

        protected = protect_aes_key(
            original_aes_key, recipient_public
        )

        with self.assertRaises(InvalidTag):
            recover_aes_key(protected, wrong_private)


if __name__ == "__main__":
    unittest.main()
