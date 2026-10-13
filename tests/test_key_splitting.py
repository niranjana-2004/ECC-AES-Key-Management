
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.aes_encryption import generate_aes_key
from src.ecc_key_protection import (
    generate_ecc_key_pair,
    protect_aes_key,
    recover_aes_key,
)
from src.key_splitting import (
    split_protected_key,
    reassemble_protected_key,
)


class TestKeySplitting(unittest.TestCase):

    def setUp(self):
        self.private_key, public_key = generate_ecc_key_pair()
        self.original_aes_key = generate_aes_key()
        self.protected_data = protect_aes_key(
            self.original_aes_key, public_key
        )

    def test_split_and_reassemble(self):
        part1, part2 = split_protected_key(self.protected_data)
        recovered = reassemble_protected_key(part1, part2)
        self.assertEqual(recovered, self.protected_data)

    def test_reassembled_package_recovers_aes_key(self):
        part1, part2 = split_protected_key(self.protected_data)
        recovered = reassemble_protected_key(part1, part2)
        recovered_key = recover_aes_key(recovered, self.private_key)
        self.assertEqual(recovered_key, self.original_aes_key)

    def test_empty_part_is_rejected(self):
        part1, part2 = split_protected_key(self.protected_data)
        with self.assertRaises(ValueError):
            reassemble_protected_key(b"", part2)


if __name__ == "__main__":
    unittest.main()
