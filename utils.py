"""
utils.py
Author: Ryan Feneley
Date: September 2024
"""

import re

def validate_username(username):
    """Validates the username format."""
    if len(username) < 3 or len(username) > 20:
        return False
    if not re.match("^[a-zA-Z0-9_]*$", username):
        return False
    return True

def validate_password(password):
    """Validates the password strength."""
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[@#$%^&+=]", password):
        return False
    return True

def validate_email(email):
    """Validates the email format."""
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

def log_error(error_message):
    """Logs an error message (placeholder for more complex logging)."""
    print(f"ERROR: {error_message}")

# Example usage
if __name__ == "__main__":
    print(validate_username("test_user"))  # True
    print(validate_password("SecureP@ssw0rd"))  # True
    print(validate_email("test@example.com"))  # True
