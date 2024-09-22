"""
auth.py
Author: Ryan Feneley
Date: September 2024
"""
import bcrypt
from db import add_user, get_user_by_username, update_user_two_factor

# Function to hash passwords
def hash_password(password: str) -> str:
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode()  # Decode the byte string to save as a string

# Function to verify passwords
def verify_password(stored_password: str, entered_password: str) -> bool:
    # Compare the stored hashed password with the entered password
    return bcrypt.checkpw(entered_password.encode(), stored_password.encode())

# Function to register a new user
def register_user(username: str, password: str, email: str) -> bool:
    # Check if the username already exists
    existing_user = get_user_by_username(username)
    if existing_user:
        print(f"Username '{username}' is already taken.")
        return False

    # Hash the password
    hashed_password = hash_password(password)

    # Add the new user to the database
    add_user(username, hashed_password, email)

    print(f"User '{username}' registered successfully.")
    return True

# Function to log in a user
def login_user(username: str, entered_password: str) -> bool:
    # Retrieve the user from the database
    user = get_user_by_username(username)
    if not user:
        print(f"User '{username}' not found.")
        return False

    # Get the stored hashed password from the user record
    stored_password = user[2]  # Assuming the password is in the 3rd column

    # Verify the entered password against the stored hash
    if verify_password(stored_password, entered_password):
        print(f"User '{username}' logged in successfully.")
        return True
    else:
        print("Incorrect password.")
        return False

# Optional: Enable or disable two-factor authentication for a user
def set_two_factor_auth(username: str, enabled: bool) -> None:
    # Retrieve the user from the database
    user = get_user_by_username(username)
    if not user:
        print(f"User '{username}' not found.")
        return

    user_id = user[0]  # Assuming the user ID is in the 1st column

    # Update two-factor authentication status
    update_user_two_factor(user_id, enabled)

    status = "enabled" if enabled else "disabled"
    print(f"Two-factor authentication {status} for user '{username}'.")

