﻿Password Manager
Overview

The Password Manager is a secure application designed to help users store and manage their passwords for various online services. It utilizes encryption to ensure that sensitive data is protected while allowing users to retrieve their passwords with ease. The application features user authentication, password encryption, and a simple graphical user interface (GUI) built with Tkinter.
Features

    User Registration and Authentication: Users can create accounts, securely store their passwords, and log in with their credentials.
    Password Storage: Store passwords with associated service names and usernames.
    Encryption: Utilizes symmetric encryption (Fernet) to encrypt passwords before storing them in the database.
    Password Retrieval: Users can view stored passwords by providing their master password.
    Database Management: Uses SQLite for storing user and password data, ensuring a lightweight and easy-to-manage backend.

Technologies Used

    Python 3.x
    Tkinter (for GUI)
    SQLite (for database)
    Cryptography library (for encryption)
    bcrypt (for password hashing)

Installation

    Clone the repository to your local machine:

    bash

git clone https://github.com/yourusername/password_manager.git
cd password_manager

Create a virtual environment (optional):

    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`

Install the required packages:

    pip install cryptography bcrypt

Run the application:

    python main.py

Usage

    Register a New User: When you first launch the application, you can register by providing a username, password, and email.
    Login: Enter your credentials to access your stored passwords.
    Add Password: After logging in, you can add a new password by specifying the service name, username, and password. The password will be encrypted before being stored.
    View Passwords: Click the "View Stored Passwords" button, enter your master password, and you will be presented with a list of your stored passwords.

Database Structure

The application uses an SQLite database with the following structure:
Users Table

    user_id: INTEGER PRIMARY KEY
    username: TEXT (unique)
    password_hash: TEXT
    email: TEXT
    two_factor_enabled: INTEGER (default 0)
    two_factor_secret: TEXT

Passwords Table

    password_id: INTEGER PRIMARY KEY
    user_id: INTEGER (foreign key)
    service_name: TEXT
    service_username: TEXT
    encrypted_password: TEXT
    notes: TEXT

Security Considerations

    Passwords are hashed using bcrypt before being stored in the database.
    Passwords are encrypted using Fernet encryption, ensuring that only authorized users can access their plaintext passwords.
    Always use a strong master password to enhance security.
