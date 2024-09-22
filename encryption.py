"""
encryption.py
Author: Ryan Feneley
Date: September 2024
"""

from cryptography.fernet import Fernet

# Function to generate a key for encryption
def generate_key() -> bytes:
    """
    Generates a key for encryption and returns it.
    The key should be securely stored, as it is needed for decryption.
    """
    return Fernet.generate_key()

# Function to save the encryption key to a file
def save_key(key: bytes, filename: str) -> None:
    """
    Saves the encryption key to a file for future use.
    """
    with open(filename, 'wb') as key_file:
        key_file.write(key)

# Function to load the encryption key from a file
def load_key(filename: str) -> bytes:
    """
    Loads the encryption key from a file.
    """
    with open(filename, 'rb') as key_file:
        return key_file.read()

# Function to encrypt a password
def encrypt_password(password: str, key: bytes) -> bytes:
    """
    Encrypts a password using the provided encryption key.
    Returns the encrypted password as bytes.
    """
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password

# Function to decrypt a password
def decrypt_password(encrypted_password: bytes, key: bytes) -> str:
    """
    Decrypts an encrypted password using the provided encryption key.
    Returns the decrypted password as a string.
    """
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password
