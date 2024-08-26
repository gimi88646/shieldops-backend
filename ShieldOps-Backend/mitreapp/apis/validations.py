from django.core.exceptions import ValidationError
import re
from bson import ObjectId
from db_connection import roles_collection


def validate_password_strength(value):
    """
    Validate that the password is strong enough.
    """
    min_length = 8

    if len(value) < min_length:
        raise ValidationError(f'Password must be at least {min_length} characters long.')

    if not re.search(r'\d', value):
        raise ValidationError('Password must contain at least one digit.')

    if not re.search(r'[A-Z]', value):
        raise ValidationError('Password must contain at least one uppercase letter.')

    if not re.search(r'[a-z]', value):
        raise ValidationError('Password must contain at least one lowercase letter.')

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
        raise ValidationError('Password must contain at least one special character.')

def validate_object_id(value):
    """
    Validate that the input is a valid MongoDB ObjectId.
    """
    try:
        ObjectId(value)
    except (TypeError, ValueError):
        raise ValidationError(f"'{value}' is not a valid ObjectId.")


def validate_roles(value):
    ALLOWED_ROLES = [ role["name"] for role in list(roles_collection.find())]

    roles_list = [role.strip() for role in value.split(',')]

    for role in roles_list:
        if role not in ALLOWED_ROLES:
            raise ValidationError(f"Invalid role: {role}. Allowed roles are {', '.join(ALLOWED_ROLES)}")

    return roles_list


