from src.access_control import Permission, has_permission


def check_permission(user, permission):
    """
    Verify that an authenticated user has
    the required permission.
    """

    if user is None:
        raise PermissionError("Authentication required.")

    if not has_permission(user["role"], permission):
        raise PermissionError(
            f"Access denied: {user['role']} "
            f"does not have {permission.value} permission."
        )

    return True


def protected_upload(user):
    check_permission(user, Permission.UPLOAD)
    print("Upload operation authorized.")


def protected_download(user):
    check_permission(user, Permission.DOWNLOAD)
    print("Download operation authorized.")


def protected_delete(user):
    check_permission(user, Permission.DELETE)
    print("Delete operation authorized.")


def protected_list(user):
    check_permission(user, Permission.LIST_DOCUMENTS)
    print("Document listing authorized.")


def protected_manage_users(user):
    check_permission(user, Permission.MANAGE_USERS)
    print("User-management operation authorized.")