import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.aes_encryption import generate_aes_key, encrypt_data


def count_different_bits(data1: bytes, data2: bytes) -> int:
    """Count the number of different bits between two byte strings."""
    if len(data1) != len(data2):
        raise ValueError("Ciphertexts must have equal length.")

    different_bits = 0

    for byte1, byte2 in zip(data1, data2):
        xor_result = byte1 ^ byte2
        different_bits += xor_result.bit_count()

    return different_bits


def main():

    print("=" * 60)
    print("AES-256-GCM AVALANCHE EFFECT TEST")
    print("=" * 60)

    # Original plaintext
    original_data = (
        b"ESKMS System 1 is a secure cloud storage "
        b"key management system using ECC and AES."
    )

    # Very small change to plaintext
    modified_data = (
        b"ESKMS System 1 is a secure cloud storage "
        b"key management system using ECC and AES!"
    )

    print("\nOriginal plaintext:")
    print(original_data.decode())

    print("\nModified plaintext:")
    print(modified_data.decode())

    # Generate one AES key
    aes_key = generate_aes_key()

    # Encrypt both plaintexts
    ciphertext1, nonce1 = encrypt_data(
        original_data,
        aes_key
    )

    ciphertext2, nonce2 = encrypt_data(
        modified_data,
        aes_key
    )

    # GCM ciphertext lengths differ because plaintext lengths differ.
    # Compare only the common ciphertext portion.
    comparison_length = min(
        len(ciphertext1),
        len(ciphertext2)
    )

    ciphertext1_common = ciphertext1[:comparison_length]
    ciphertext2_common = ciphertext2[:comparison_length]

    different_bits = count_different_bits(
        ciphertext1_common,
        ciphertext2_common
    )

    total_bits = comparison_length * 8

    avalanche_percentage = (
        different_bits / total_bits
    ) * 100

    print("\n" + "=" * 60)
    print("AVALANCHE EFFECT RESULTS")
    print("=" * 60)

    print(
        f"\nOriginal ciphertext size: "
        f"{len(ciphertext1)} bytes"
    )

    print(
        f"Modified ciphertext size: "
        f"{len(ciphertext2)} bytes"
    )

    print(
        f"Compared ciphertext size: "
        f"{comparison_length} bytes"
    )

    print(
        f"\nDifferent bits: "
        f"{different_bits}"
    )

    print(
        f"Total compared bits: "
        f"{total_bits}"
    )

    print(
        f"\nAvalanche effect: "
        f"{avalanche_percentage:.2f}%"
    )

    print("\n" + "=" * 60)
    print("AVALANCHE EFFECT TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()