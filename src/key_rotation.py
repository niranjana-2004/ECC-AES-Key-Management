
from src.ecc_key_protection import (
    generate_ecc_key_pair,
    protect_aes_key,
    recover_aes_key,
)


def rotate_ecc_key_pair(
    old_protected_package: dict,
    old_private_key,
):
    """
    Rotate the ECC key pair while keeping the AES data key unchanged.

    Returns the new private key, new public key, and the AES key
    protected for the new public key.
    """
    # Recover the existing AES key using the old private key.
    aes_key = recover_aes_key(
        old_protected_package,
        old_private_key,
    )

    # Generate a new ECC key pair.
    new_private_key, new_public_key = generate_ecc_key_pair()

    # Protect the same AES key for the new ECC public key.
    new_protected_package = protect_aes_key(
        aes_key,
        new_public_key,
    )

    return new_private_key, new_public_key, new_protected_package
