
import os
from pathlib import Path

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError


BUCKET_NAME = "eskms-encrypted-files"
ENDPOINT_URL = os.getenv(
    "MINIO_ENDPOINT_URL",
    "http://localhost:9000",
)


def get_s3_client():
    """Create an S3-compatible client for local MinIO."""

    access_key = os.getenv("MINIO_ROOT_USER")
    secret_key = os.getenv("MINIO_ROOT_PASSWORD")

    if not access_key or not secret_key:
        raise EnvironmentError(
            "MINIO_ROOT_USER and MINIO_ROOT_PASSWORD "
            "environment variables must be configured."
        )

    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT_URL,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-east-1",
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
        ),
    )


def check_bucket() -> bool:
    """Check whether the configured bucket is accessible."""

    client = get_s3_client()

    try:
        client.head_bucket(Bucket=BUCKET_NAME)
        return True
    except ClientError:
        return False


def upload_file(
    local_path: str,
    object_name: str | None = None,
) -> str:
    """Upload a file to MinIO."""

    source = Path(local_path)

    if not source.is_file():
        raise FileNotFoundError(
            f"File not found: {source}"
        )

    if not check_bucket():
        raise RuntimeError(
            f"Bucket '{BUCKET_NAME}' is unavailable."
        )

    if object_name is None:
        object_name = source.name

    client = get_s3_client()

    client.upload_file(
        str(source),
        BUCKET_NAME,
        object_name,
    )

    return object_name


def download_file(
    object_name: str,
    destination_path: str,
) -> str:
    """Download an object from MinIO."""

    destination = Path(destination_path)
    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    client = get_s3_client()

    client.download_file(
        BUCKET_NAME,
        object_name,
        str(destination),
    )

    return str(destination)


def delete_file(object_name: str) -> None:
    """Delete an object from MinIO."""

    client = get_s3_client()

    client.delete_object(
        Bucket=BUCKET_NAME,
        Key=object_name,
    )


def list_files() -> list[str]:
    """List objects stored in the project bucket."""

    client = get_s3_client()

    response = client.list_objects_v2(
        Bucket=BUCKET_NAME
    )

    return [
        item["Key"]
        for item in response.get("Contents", [])
    ]
