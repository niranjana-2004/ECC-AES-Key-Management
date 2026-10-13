
import unittest

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
        self.original_aes_key = generate_aes_key()
        self.private_key, self.public_key = generate_ecc_key_pair()
        self.protected_package = protect_aes_key(
            self.original_aes_key,
            self.public_key,
        )

    def test_split_and_reassemble(self):
        metadata, part1, part2 = split_protected_key(
            self.protected_package
        )

        recovered = reassemble_protected_key(metadata, part1, part2)

        self.assertEqual(
            recovered["wrapped_key"],
            self.protected_package["wrapped_key"],
        )
        self.assertEqual(
            recovered["ephemeral_public_key"],
            self.protected_package["ephemeral_public_key"],
        )
        self.assertEqual(recovered["salt"], self.protected_package["salt"])
        self.assertEqual(recovered["nonce"], self.protected_package["nonce"])

    def test_reassembled_package_recovers_aes_key(self):
        metadata, part1, part2 = split_protected_key(
            self.protected_package
        )

        recovered = reassemble_protected_key(metadata, part1, part2)
        recovered_key = recover_aes_key(recovered, self.private_key)

        self.assertEqual(recovered_key, self.original_aes_key)

    def test_empty_part_is_rejected(self):
        metadata, part1, part2 = split_protected_key(
            self.protected_package
        )

        with self.assertRaises(ValueError):
            reassemble_protected_key(metadata, b"", part2)

        with self.assertRaises(ValueError):
            reassemble_protected_key(metadata, part1, b"")


if __name__ == "__main__":
    unittest.main()
