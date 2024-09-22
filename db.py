"""
db.py
Ryan Feneley
September 2024
"""

import sqlite3
from sqlite3 import Error
import os
from contextlib import contextmanager

# Define the path to the database file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "password_manager.db")


@contextmanager
def get_db_connection():
    """
    Context manager for SQLite database connections.
    Ensures that connections are properly closed after operations.
    Enables foreign key constraints.
    """
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.execute("PRAGMA foreign_keys = 1")  # Enable foreign key support
        yield conn
    except Error as e:
        print(f"Database connection error: {e}")
        yield None
    finally:
        if conn:
            conn.close()


def initialize_db():
    """
    Initializes the database by creating necessary tables if they do not exist.
    Tables:
        - users: Stores user credentials and 2FA settings.
        - passwords: Stores encrypted passwords associated with users.
    """
    create_users_table = """
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT,
        two_factor_enabled INTEGER DEFAULT 0,
        two_factor_secret TEXT
    );
    """

    create_passwords_table = """
    CREATE TABLE IF NOT EXISTS passwords (
        password_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        service_name TEXT NOT NULL,
        service_username TEXT NOT NULL,
        encrypted_password TEXT NOT NULL,
        notes TEXT,
        FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
    );
    """

    with get_db_connection() as conn:
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute(create_users_table)
                cursor.execute(create_passwords_table)
                conn.commit()
                print("Database initialized successfully.")
            except Error as e:
                print(f"Error initializing database: {e}")
        else:
            print("Failed to initialize database due to connection issues.")


# -------------------- User Operations -------------------- #

def add_user(username, password_hash, email=None):
    """
    Adds a new user to the users table.
    
    Parameters:
        username (str): Unique username for the user.
        password_hash (str): Hashed password using bcrypt.
        email (str, optional): User's email address.
    
    Returns:
        bool: True if user added successfully, False otherwise.
    """
    insert_user_sql = """
    INSERT INTO users (username, password_hash, email)
    VALUES (?, ?, ?);
    """
    with get_db_connection() as conn:
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute(insert_user_sql, (username, password_hash, email))
                conn.commit()
                print(f"User '{username}' added successfully.")
                return True
            except sqlite3.IntegrityError:
                print(f"Username '{username}' already exists.")
            except Error as e:
                print(f"Error adding user: {e}")
    return False


def get_user_by_username(username):
    """
    Retrieves a user's details by their username.
    
    Parameters:
        username (str): The username to search for.
    
    Returns:
        tuple or None: User record if found, else None.
    """
    select_user_sql = """
    SELECT * FROM users WHERE username = ?;
    """
    with get_db_connection() as conn:
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute(select_user_sql, (username,))
                user = cursor.fetchone()
                return user
            except Error as e:
                print(f"Error retrieving user: {e}")
    return None


def get_user_by_id(user_id):
    """
    Retrieves a user's details by their user ID.
    
    Parameters:
        user_id (int): The user ID to search for.
    
    Returns:
        tuple or None: User record if found, else None.
    """
    select_user_sql = """
    SELECT * FROM users WHERE user_id = ?;
    """
    with get_db_connection() as conn:
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute(select_user_sql, (user_id,))
                user = cursor.fetchone()
                return user
            except Error as e:
                print(f"Error retrieving user by ID: {e}")
    return None


def update_two_factor(user_id, enabled, secret=None):
    """
    Updates a user's two-factor authentication settings.
    
    Parameters:
        user_id (int): The ID of the user to update.
        enabled (int): 1 to enable 2FA, 0 to disable.
        secret (str, optional): Secret key for 2FA (e.g., TOTP secret).
    
    Returns:
        bool: True if update was successful, False otherwise.
    """
    update_2fa_sql = """
    UPDATE users
    SET two_factor_enabled = ?, two_factor_secret = ?
    WHERE user_id = ?;
    """
    with get_db_connection() as conn:
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute(update_2fa_sql, (enabled, secret, user_id))
                conn.commit()
                print(f"Two-factor authentication updated for user ID {user_id}.")
                return True
            except Error as e:
                print(f"Error updating two-factor authentication: {e}")
    return False


def delete_user(user_id):
    """
    Deletes a user from the users table. This will also delete all associated passwords due to ON DELETE CASCADE.
    
    Parameters:
        user_id (int): The ID of the user to delete.
    
    Returns:
        bool: True if deletion was successful, False otherwise.
    """
    delete_user_sql = """
    DELETE FROM users WHERE user_id = ?;
    """
    with get_db_connection() as conn:
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute(delete_user_sql, (user_id,))
                conn.commit()
                print(f"User ID {user_id} deleted successfully.")
                return True
            except Error as e:
                print(f"Error deleting user: {e}")
    return False


# -------------------- Password Operations -------------------- #

def add_password(user_id, service_name, service_username, encrypted_password, notes=None):
    """
    Adds a new password entry for a user.
    
    Parameters:
        user_id (int): The ID of the user owning this password.
        service_name (str): Name of the service (e.g., GitHub).
        service_username (str): Username for the service.
        encrypted_password (str): Encrypted password.
        notes (str, optional): Any additional notes.
    
    Returns:
        bool: True if password added successfully, False otherwise.
    """
    insert_password_sql = """
    INSERT INTO passwords (user_id, service_name, service_username, encrypted_password, notes)
    VALUES (?, ?, ?, ?, ?);
    """
    with get_db_connection() as conn:
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute(insert_password_sql, (user_id, service_name, service_username, encrypted_password, notes))
                conn.commit()
                print(f"Password for '{service_name}' added successfully.")
                return True
            except Error as e:
                print(f"Error adding password: {e}")
    return False


def get_passwords(user_id):
    """
    Retrieves all password entries for a specific user.
    
    Parameters:
        user_id (int): The ID of the user.
    
    Returns:
        list of tuples: List containing password records.
    """
    select_passwords_sql = """
    SELECT password_id, service_name, service_username, encrypted_password, notes
    FROM passwords
    WHERE user_id = ?;
    """
    with get_db_connection() as conn:
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute(select_passwords_sql, (user_id,))
                passwords = cursor.fetchall()
                return passwords
            except Error as e:
                print(f"Error retrieving passwords: {e}")
    return []


def get_password_by_id(password_id):
    """
    Retrieves a specific password entry by its ID.
    
    Parameters:
        password_id (int): The ID of the password entry.
    
    Returns:
        tuple or None: Password record if found, else None.
    """
    select_password_sql = """
    SELECT password_id, service_name, service_username, encrypted_password, notes
    FROM passwords
    WHERE password_id = ?;
    """
    with get_db_connection() as conn:
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute(select_password_sql, (password_id,))
                password = cursor.fetchone()
                return password
            except Error as e:
                print(f"Error retrieving password by ID: {e}")
    return None


def update_password(password_id, service_name=None, service_username=None, encrypted_password=None, notes=None):
    """
    Updates an existing password entry. Only provided fields will be updated.
    
    Parameters:
        password_id (int): The ID of the password entry to update.
        service_name (str, optional): New service name.
        service_username (str, optional): New service username.
        encrypted_password (str, optional): New encrypted password.
        notes (str, optional): New notes.
    
    Returns:
        bool: True if update was successful, False otherwise.
    """
    fields = []
    values = []

    if service_name is not None:
        fields.append("service_name = ?")
        values.append(service_name)
    if service_username is not None:
        fields.append("service_username = ?")
        values.append(service_username)
    if encrypted_password is not None:
        fields.append("encrypted_password = ?")
        values.append(encrypted_password)
    if notes is not None:
        fields.append("notes = ?")
        values.append(notes)

    if not fields:
        print("No fields provided to update.")
        return False  # Nothing to update

    update_password_sql = f"""
    UPDATE passwords
    SET {', '.join(fields)}
    WHERE password_id = ?;
    """
    values.append(password_id)

    with get_db_connection() as conn:
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute(update_password_sql, tuple(values))
                if cursor.rowcount == 0:
                    print(f"No password entry found with ID {password_id}.")
                    return False
                conn.commit()
                print(f"Password ID {password_id} updated successfully.")
                return True
            except Error as e:
                print(f"Error updating password: {e}")
    return False


def delete_password(password_id):
    """
    Deletes a password entry from the database.
    
    Parameters:
        password_id (int): The ID of the password entry to delete.
    
    Returns:
        bool: True if deletion was successful, False otherwise.
    """
    delete_password_sql = """
    DELETE FROM passwords WHERE password_id = ?;
    """
    with get_db_connection() as conn:
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute(delete_password_sql, (password_id,))
                if cursor.rowcount == 0:
                    print(f"No password entry found with ID {password_id}.")
                    return False
                conn.commit()
                print(f"Password ID {password_id} deleted successfully.")
                return True
            except Error as e:
                print(f"Error deleting password: {e}")
    return False


# -------------------- Utility Functions -------------------- #

def user_exists(username):
    """
    Checks if a user with the given username exists.
    
    Parameters:
        username (str): The username to check.
    
    Returns:
        bool: True if user exists, False otherwise.
    """
    user = get_user_by_username(username)
    return user is not None


def password_entry_exists(password_id):
    """
    Checks if a password entry with the given ID exists.
    
    Parameters:
        password_id (int): The password ID to check.
    
    Returns:
        bool: True if password entry exists, False otherwise.
    """
    password = get_password_by_id(password_id)
    return password is not None


# -------------------- Initialization -------------------- #

if __name__ == "__main__":
    """
    Test script to verify the functionality of the db.py module.
    This will only run when executing db.py directly.
    """
    import bcrypt

    def test_database():
        # Initialize the database
        initialize_db()

        # Example user data
        username = "testuser"
        password = "SecureP@ssw0rd!"
        email = "testuser@example.com"

        # Hash the password using bcrypt
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

        # Add a new user
        if add_user(username, password_hash, email):
            # Retrieve the user
            user = get_user_by_username(username)
            print("Retrieved User:", user)

            if user:
                user_id = user[0]  # Assuming user_id is the first field

                # Add a password entry for the user
                service_name = "GitHub"
                service_username = "testuser_github"
                encrypted_password = "EncryptedPassword123!"
                notes = "My GitHub account"

                if add_password(user_id, service_name, service_username, encrypted_password, notes):
                    # Retrieve all passwords for the user
                    passwords = get_passwords(user_id)
                    print("Retrieved Passwords:", passwords)

                    if passwords:
                        password_id = passwords[0][0]  # Assuming password_id is the first field

                        # Update the password entry
                        new_encrypted_password = "NewEncryptedPassword456!"
                        update_password(password_id, encrypted_password=new_encrypted_password)

                        # Retrieve updated passwords
                        updated_passwords = get_passwords(user_id)
                        print("Updated Passwords:", updated_passwords)

                        # Delete the password entry
                        delete_password(password_id)

                        # Verify deletion
                        final_passwords = get_passwords(user_id)
                        print("Final Passwords after Deletion:", final_passwords)

                # Update two-factor authentication settings
                update_two_factor(user_id, enabled=1, secret="SecretCodeExample")

                # Optionally, delete the user
                # delete_user(user_id)

    test_database()
