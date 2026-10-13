
import base64
import json


def split_protected_key(protected_data: dict) -> tuple[dict, bytes, bytes]:
    """
    Split only the encrypted AES-key payload.

    The ECC public-key data, salt, and nonce remain as metadata
    required to recover the AES key.
    """
    required_fields = {
        "ephemeral_public_key",
        "salt",
        "nonce",
        "wrapped_key",
    }

    if not isinstance(protected_data, dict):
        raise TypeError("Protected key data must be a dictionary.")

    if set(protected_data.keys()) != required_fields:
        raise ValueError("Missing or unexpected key-package fields.")

    for field in required_fields:
        if not isinstance(protected_data[field], bytes):
            raise TypeError(f"Expected bytes for field: {field}")

    wrapped_key = protected_data["wrapped_key"]

    if len(wrapped_key) < 2:
        raise ValueError("Wrapped key is too short to split.")

    midpoint = (len(wrapped_key) + 1) // 2

    metadata = {
        "ephemeral_public_key": protected_data["ephemeral_public_key"],
        "salt": protected_data["salt"],
        "nonce": protected_data["nonce"],
    }

    part1 = wrapped_key[:midpoint]
    part2 = wrapped_key[midpoint:]

    return metadata, part1, part2


def reassemble_protected_key(
    metadata: dict,
    part1: bytes,
    part2: bytes,
) -> dict:
    """Reassemble the encrypted AES-key payload and its metadata."""
    if not isinstance(metadata, dict):
        raise TypeError("Metadata must be a dictionary.")

    required_metadata = {
        "ephemeral_public_key",
        "salt",
        "nonce",
    }

    if set(metadata.keys()) != required_metadata:
        raise ValueError("Missing or unexpected metadata fields.")

    for field in required_metadata:
        if not isinstance(metadata[field], bytes):
            raise TypeError(f"Expected bytes for field: {field}")

    if not isinstance(part1, bytes) or not isinstance(part2, bytes):
        raise TypeError("Both key parts must be bytes.")

    if not part1 or not part2:
        raise ValueError("Both key parts must be non-empty.")

    return {
        **metadata,
        "wrapped_key": part1 + part2,
    }


def serialize_protected_key(protected_data: dict) -> bytes:
    """Serialize the complete protected-key package for size measurement."""
    required_fields = {
        "ephemeral_public_key",
        "salt",
        "nonce",
        "wrapped_key",
    }

    if not isinstance(protected_data, dict):
        raise TypeError("Protected key data must be a dictionary.")

    if set(protected_data.keys()) != required_fields:
        raise ValueError("Missing or unexpected key-package fields.")

    encoded = {}

    for name, value in protected_data.items():
        if not isinstance(value, bytes):
            raise TypeError(f"Expected bytes for field: {name}")
        encoded[name] = base64.b64encode(value).decode("ascii")

    return json.dumps(encoded, sort_keys=True).encode("utf-8")
