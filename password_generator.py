"""
password_generator.py
Author: Ryan Feneley
Date: September 2024
"""

import random
import string

def generate_password(length=12, use_uppercase=True, use_numbers=True, use_special=True):
    """
    Generates a random password containing letters, digits, and special characters.
    
    :param length: Length of the password to generate. Default is 12.
    :param use_uppercase: Whether to include uppercase letters. Default is True.
    :param use_numbers: Whether to include numbers. Default is True.
    :param use_special: Whether to include special characters. Default is True.
    :return: Generated password as a string.
    """
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase if use_uppercase else ''
    numbers = string.digits if use_numbers else ''
    special = string.punctuation if use_special else ''

    # Combine all character sets
    all_characters = lowercase + uppercase + numbers + special

    if not all_characters:
        raise ValueError("At least one character type must be selected.")

    # Generate the password
    password = ''.join(random.choice(all_characters) for _ in range(length))

    return password

# Example usage
if __name__ == "__main__":
    print("Generated Password:", generate_password(length=16))
