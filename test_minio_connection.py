
from src.cloud_storage import (
    get_s3_client,
    check_bucket,
    list_files,
)

print("Connecting to MinIO...")

client = get_s3_client()

print("S3 client created successfully!")

if check_bucket():
    print("Bucket access successful!")
    print("Bucket: eskms-encrypted-files")

    print("\nExisting objects:")
    files = list_files()

    if files:
        for filename in files:
            print("-", filename)
    else:
        print("Bucket is currently empty.")

else:
    print("Bucket access failed!")
