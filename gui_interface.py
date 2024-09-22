"""
gui_interface.py
Author: Ryan Feneley
Date: September 2024
"""

import tkinter as tk
import bcrypt
from tkinter import messagebox, simpledialog
from db import Database
from password_generator import generate_password

class PasswordManagerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager")
        self.db = Database()
        self.current_user_id = None

        # Create UI Elements
        self.create_widgets()

    def create_widgets(self):
        # Login
        self.login_frame = tk.Frame(self.master)
        self.login_frame.pack(pady=10)

        self.username_label = tk.Label(self.login_frame, text="Username:")
        self.username_label.grid(row=0, column=0)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1)

        self.password_label = tk.Label(self.login_frame, text="Password:")
        self.password_label.grid(row=1, column=0)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1)

        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.grid(row=2, columnspan=2)

        self.register_button = tk.Button(self.master, text="Register", command=self.register)
        self.register_button.pack(pady=5)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if self.db.authenticate_user(username, password):
            messagebox.showinfo("Login Successful", "Welcome!")
            user = self.db.get_user_by_username(username)
            self.current_user_id = user[0]
            self.show_dashboard()
        else:
            messagebox.showerror("Login Failed", "Invalid credentials.")

    def show_dashboard(self):
        for widget in self.master.winfo_children():
            widget.destroy()
        dashboard_frame = tk.Frame(self.master)
        dashboard_frame.pack(pady=10)

        welcome_label = tk.Label(dashboard_frame, text="Welcome to your Password Manager!")
        welcome_label.pack()

        view_passwords_button = tk.Button(dashboard_frame, text="View Stored Passwords", command=self.view_passwords)
        view_passwords_button.pack(pady=5)

        generate_button = tk.Button(dashboard_frame, text="Generate Password", command=self.generate_and_display_password)
        generate_button.pack(pady=5)

        add_password_button = tk.Button(dashboard_frame, text="Add Password", command=self.add_password)
        add_password_button.pack(pady=5)

        remove_password_button = tk.Button(dashboard_frame, text="Remove Password", command=self.remove_password)
        remove_password_button.pack(pady=5)


        logout_button = tk.Button(dashboard_frame, text="Logout", command=self.logout)
        logout_button.pack(pady=5)

    def logout(self):
        for widget in self.master.winfo_children():
            widget.destroy()
        self.current_user_id = None
        self.create_widgets()

    def register(self):
        username = simpledialog.askstring("Register", "Enter a username:")
        password = simpledialog.askstring("Register", "Enter a password:", show="*")
        if username and password:
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
            if self.db.add_user(username, password_hash):
                messagebox.showinfo("Registration Successful", "User created successfully!")
            else:
                messagebox.showerror("Registration Failed", "Username already exists.")
        else:
            messagebox.showwarning("Registration Failed", "Please enter both username and password.")

    def generate_and_display_password(self):
        password = generate_password()
        messagebox.showinfo("Generated Password", f"Your password: {password}")

    def view_passwords(self):
        if self.current_user_id:
            passwords = self.db.get_passwords(self.current_user_id)
            if passwords:
                password_list = "\n".join([f"Service: {entry[1]}, Username: {entry[2]}, Password: {entry[3]}" for entry in passwords])
                messagebox.showinfo("Stored Passwords", password_list)
            else:
                messagebox.showinfo("Stored Passwords", "No passwords stored.")
        else:
            messagebox.showerror("Error", "Please log in to view passwords.")


    def add_password(self):
        service_name = simpledialog.askstring("Add Password", "Enter the service name:")
        service_username = simpledialog.askstring("Add Password", "Enter the username for the service:")
        encrypted_password = simpledialog.askstring("Add Password", "Enter the password (or generated password):")

        if service_name and service_username and encrypted_password:
            if self.db.add_password(self.current_user_id, service_name, service_username, encrypted_password):
                messagebox.showinfo("Success", "Password added successfully!")
            else:
                messagebox.showerror("Error", "Failed to add password.")
        else:
            messagebox.showwarning("Input Error", "Please fill in all fields.")

    def remove_password(self):
        service_name = simpledialog.askstring("Remove Password", "Enter the service name to remove:")
        if service_name:
            service_password = simpledialog.askstring("Confirm Removal", f"Enter the password for {service_name} to confirm removal:", show="*")
            if service_password:
                # Fetch the password for the service to validate
                user_passwords = self.db.get_passwords(self.current_user_id)
                for entry in user_passwords:
                    if entry[1] == service_name:
                        if bcrypt.checkpw(service_password.encode('utf-8'), entry[3].encode('utf-8')):
                            if self.db.remove_password(self.current_user_id, service_name):
                                messagebox.showinfo("Success", f"Password for {service_name} removed successfully!")
                            else:
                                messagebox.showerror("Error", f"Could not remove password for {service_name}.")
                            return
                messagebox.showerror("Error", "Service name or password is incorrect.")
            else:
                messagebox.showwarning("Warning", "No password entered.")
        else:
            messagebox.showwarning("Warning", "No service name entered.")



def start_gui():
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    start_gui()
