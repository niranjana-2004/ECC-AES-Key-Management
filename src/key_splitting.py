
import base64
import json


def serialize_protected_key(protected_data: dict) -> bytes:
    """Serialize protected key components into JSON bytes."""
    encoded = {}

    for name, value in protected_data.items():
        if not isinstance(value, bytes):
            raise TypeError(f"Expected bytes for field: {name}")
        encoded[name] = base64.b64encode(value).decode("ascii")

    return json.dumps(encoded, sort_keys=True).encode("utf-8")


def split_protected_key(protected_data: dict) -> tuple[bytes, bytes]:
    """Split the serialized protected-key package into two parts."""
    serialized = serialize_protected_key(protected_data)
    midpoint = (len(serialized) + 1) // 2

    return serialized[:midpoint], serialized[midpoint:]


def reassemble_protected_key(part1: bytes, part2: bytes) -> dict:
    """Reassemble and validate a serialized protected-key package."""
    if not isinstance(part1, bytes) or not isinstance(part2, bytes):
        raise TypeError("Both parts must be bytes.")

    if not part1 or not part2:
        raise ValueError("Both key parts must be non-empty.")

    try:
        encoded = json.loads((part1 + part2).decode("utf-8"))

        if not isinstance(encoded, dict):
            raise ValueError("Invalid protected-key package.")

        required_fields = {
            "ephemeral_public_key",
            "salt",
            "nonce",
            "wrapped_key",
        }

        if set(encoded.keys()) != required_fields:
            raise ValueError("Missing or unexpected key-package fields.")

        protected_data = {}

        for name, value in encoded.items():
            if not isinstance(value, str):
                raise ValueError("Invalid protected-key package encoding.")

            protected_data[name] = base64.b64decode(
                value, validate=True
            )

        return protected_data

    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "Unable to reassemble protected-key package."
        ) from exc

    except (base64.binascii.Error, ValueError) as exc:
        raise ValueError(
            "Invalid protected-key package encoding."
        ) from exc
