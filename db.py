"""
db.py
Author: Ryan Feneley
Date: September 2024
"""
import sqlite3
from sqlite3 import Error
import os
from contextlib import contextmanager
import bcrypt

# Define the path to the database file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "password_manager.db")

@contextmanager
def get_db_connection():
    """Context manager for SQLite database connections."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.execute("PRAGMA foreign_keys = 1")
        yield conn
    except Error as e:
        print(f"Database connection error: {e}")
        yield None
    finally:
        if conn:
            conn.close()

def initialize_db():
    """Initializes the database by creating necessary tables if they do not exist."""
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

class Database:
    """Database class to manage user and password operations."""
    
    def __init__(self, db_path=DATABASE_PATH):
        self.db_path = db_path
        initialize_db()

    def add_user(self, username, password_hash, email=None):
        """Adds a new user to the users table."""
        insert_user_sql = "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?);"
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

    def authenticate_user(self, username, password):
        """Authenticates a user by verifying username and password."""
        user = self.get_user_by_username(username)
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            return True
        return False

    def get_user_by_username(self, username):
        """Retrieves a user's details by their username."""
        select_user_sql = "SELECT * FROM users WHERE username = ?;"
        with get_db_connection() as conn:
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute(select_user_sql, (username,))
                    return cursor.fetchone()
                except Error as e:
                    print(f"Error retrieving user: {e}")
        return None

    def get_passwords(self, user_id):
        """Retrieves all password entries for a specific user."""
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
                    return cursor.fetchall()
                except Error as e:
                    print(f"Error retrieving passwords: {e}")
        return []

    def add_password(self, user_id, service_name, service_username, password, notes=None):
        """Adds a new password entry for a user."""
        salt = bcrypt.gensalt()
        encrypted_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
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

    
    def remove_password(self, user_id, service_name):
        """Removes a password entry for a user."""
        delete_password_sql = "DELETE FROM passwords WHERE user_id = ? AND service_name = ?;"
        with get_db_connection() as conn:
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute(delete_password_sql, (user_id, service_name))
                    conn.commit()
                    return cursor.rowcount > 0  # Returns True if a row was deleted
                except Error as e:
                    print(f"Error removing password: {e}")
        return False



    def get_all_passwords(self, user_id):
        """Fetches all passwords for the specified user."""
        return self.get_passwords(user_id)

# Initialization for testing purposes
if __name__ == "__main__":
    db = Database()
    test_username = "testuser"
    test_password = "SecureP@ssw0rd!"
    salt = bcrypt.gensalt()
    test_password_hash = bcrypt.hashpw(test_password.encode('utf-8'), salt).decode('utf-8')
    
    db.add_user(test_username, test_password_hash)
    user = db.get_user_by_username(test_username)
    print("Retrieved User:", user)
