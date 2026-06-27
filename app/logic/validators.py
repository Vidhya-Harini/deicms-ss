"""
Password-strength policy. Enforces complexity rules on new passwords.
"""
import re

MIN_LENGTH = 12


def validate_password_strength(password: str):
    """
    Return a list of human-readable rule violations for `password`.
    An empty list means the password satisfies the policy.
    """
    errors = []
    if len(password or '') < MIN_LENGTH:
        errors.append(f'be at least {MIN_LENGTH} characters long')
    if not re.search(r'[A-Z]', password or ''):
        errors.append('contain an uppercase letter')
    if not re.search(r'[a-z]', password or ''):
        errors.append('contain a lowercase letter')
    if not re.search(r'[0-9]', password or ''):
        errors.append('contain a digit')
    if not re.search(r'[^A-Za-z0-9]', password or ''):
        errors.append('contain a special character')
    return errors
