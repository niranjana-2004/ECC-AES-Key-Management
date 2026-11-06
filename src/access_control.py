from enum import Enum


class Role(Enum):
    ADMIN = "ADMIN"
    USER = "USER"
    VIEWER = "VIEWER"


class Permission(Enum):
    UPLOAD = "UPLOAD"
    DOWNLOAD = "DOWNLOAD"
    DELETE = "DELETE"
    LIST_DOCUMENTS = "LIST_DOCUMENTS"
    MANAGE_USERS = "MANAGE_USERS"


ROLE_PERMISSIONS = {
    Role.ADMIN: {
        Permission.UPLOAD,
        Permission.DOWNLOAD,
        Permission.DELETE,
        Permission.LIST_DOCUMENTS,
        Permission.MANAGE_USERS,
    },

    Role.USER: {
        Permission.UPLOAD,
        Permission.DOWNLOAD,
        Permission.LIST_DOCUMENTS,
    },

    Role.VIEWER: {
        Permission.LIST_DOCUMENTS,
    },
}


def has_permission(role, permission):
    """
    Check whether a role has a specific permission.
    """

    if isinstance(role, str):
        try:
            role = Role(role.upper())
        except ValueError:
            return False

    if isinstance(permission, str):
        try:
            permission = Permission(permission.upper())
        except ValueError:
            return False

    return permission in ROLE_PERMISSIONS.get(role, set())


def get_permissions(role):
    """
    Return all permissions assigned to a role.
    """

    if isinstance(role, str):
        try:
            role = Role(role.upper())
        except ValueError:
            return set()

    return ROLE_PERMISSIONS.get(role, set())