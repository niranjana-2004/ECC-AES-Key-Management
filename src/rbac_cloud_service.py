from pathlib import Path

from src.access_control import Permission, has_permission
from src.cloud_storage import (
    upload_file,
    download_file,
    delete_file,
    list_files,
)


def check_permission(user, permission):
    """
    Verify that the authenticated user has
    the required permission.
    """

    if user is None:
        raise PermissionError("Authentication required.")

    if not has_permission(user["role"], permission):
        raise PermissionError(
            f"Access denied: {user['role']} "
            f"does not have {permission.value} permission."
        )


def upload_document(user, local_path, object_name=None):
    """
    Upload a document after checking RBAC permission.
    """

    check_permission(user, Permission.UPLOAD)

    return upload_file(
        local_path=local_path,
        object_name=object_name
    )


def download_document(user, object_name, destination_path):
    """
    Download a document after checking RBAC permission.
    """

    check_permission(user, Permission.DOWNLOAD)

    return download_file(
        object_name=object_name,
        destination_path=destination_path
    )


def delete_document(user, object_name):
    """
    Delete a document after checking RBAC permission.
    """

    check_permission(user, Permission.DELETE)

    return delete_file(object_name)


def list_documents(user):
    """
    List cloud documents after checking RBAC permission.
    """

    check_permission(user, Permission.LIST_DOCUMENTS)

    return list_files()