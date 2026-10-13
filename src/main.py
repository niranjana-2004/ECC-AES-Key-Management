
from pathlib import Path

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
from src.file_service import encrypt_file, decrypt_file


def run_demo():
    project_root = Path(__file__).resolve().parent.parent
    sample_file = project_root / "sample_data" / "research_note.txt"
    output_dir = project_root / "results"

    encrypted_file = output_dir / "research_note.enc"
    decrypted_file = output_dir / "research_note_recovered.txt"

    if not sample_file.is_file():
        raise FileNotFoundError(
            f"Sample file not found: {sample_file}\n"
            "Create sample_data/research_note.txt first."
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate AES key and encrypt the actual file
    aes_key = generate_aes_key()
    metadata = encrypt_file(
        str(sample_file),
        str(encrypted_file),
        aes_key,
    )
    print("[1] File encrypted successfully.")

    # 2. Protect the AES key using ECC-based key wrapping
    recipient_private_key, recipient_public_key = (
        generate_ecc_key_pair()
    )
    protected_package = protect_aes_key(
        aes_key,
        recipient_public_key,
    )
    print("[2] AES key protected successfully.")

    # 3. Split and reconstruct the protected-key package
    part1, part2 = split_protected_key(protected_package)
    print("[3] Protected-key package split into two parts.")

    reconstructed_package = reassemble_protected_key(part1, part2)
    print("[4] Protected-key package reassembled.")

    # 4. Recover the AES key
    recovered_key = recover_aes_key(
        reconstructed_package,
        recipient_private_key,
    )
    print("[5] AES key recovered successfully.")

    # 5. Decrypt the file using the recovered key and nonce
    decrypt_file(
        str(encrypted_file),
        str(decrypted_file),
        recovered_key,
        metadata["nonce"],
    )
    print("[6] File decrypted successfully.")

    # 6. Compare original and recovered files byte by byte
    original_data = sample_file.read_bytes()
    recovered_data = decrypted_file.read_bytes()

    if original_data != recovered_data:
        raise RuntimeError("Verification failed: file contents differ.")

    print("[7] Verification successful!")
    print(f"Original file:  {sample_file}")
    print(f"Encrypted file: {encrypted_file}")
    print(f"Restored file:  {decrypted_file}")
    print(f"Original size:  {metadata['original_size']} bytes")
    print(f"Encrypted size: {metadata['encrypted_size']} bytes")
    print("SUCCESS: Original and recovered files are identical.")


if __name__ == "__main__":
    run_demo()
