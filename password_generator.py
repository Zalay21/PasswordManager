import secrets
import string
import json
from cryptography.fernet import Fernet
import bcrypt
import os
import tkinter as tk
from tkinter import messagebox, simpledialog

USER_DATA_DIR = "user_data"

# Generate a secure password
def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

# Save an encryption key for a user
def save_key(username, key):
    with open(f"{USER_DATA_DIR}/{username}_key.key", "wb") as key_file:
        key_file.write(key)

# Load the encryption key for a user
def load_key(username):
    with open(f"{USER_DATA_DIR}/{username}_key.key", "rb") as key_file:
        return key_file.read()

# Encrypt a password
def encrypt_password(password, key):
    cipher = Fernet(key)
    return cipher.encrypt(password.encode())

# Decrypt a password
def decrypt_password(encrypted_password, key):
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_password).decode()

# Load all passwords for a user
def load_passwords(username):
    user_file = f"{USER_DATA_DIR}/{username}_passwords.json"
    if not os.path.exists(user_file):
        return {}
    with open(user_file, "r") as file:
        return json.load(file)

# Save all passwords for a user
def save_passwords(username, passwords):
    user_file = f"{USER_DATA_DIR}/{username}_passwords.json"
    with open(user_file, "w") as file:
        json.dump(passwords, file, indent=4)

# Check if a user exists
def user_exists(username):
    return os.path.exists(f"{USER_DATA_DIR}/{username}_key.key")

# Save a hashed master password
def save_master_password(username, master_password):
    hashed_password = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())
    with open(f"{USER_DATA_DIR}/{username}_master.hash", "wb") as hash_file:
        hash_file.write(hashed_password)

# Verify the master password
def verify_master_password(username, master_password):
    with open(f"{USER_DATA_DIR}/{username}_master.hash", "rb") as hash_file:
        stored_hashed_password = hash_file.read()
    return bcrypt.checkpw(master_password.encode(), stored_hashed_password)

# GUI for managing passwords
def password_manager(username, encryption_key):
    def add_password():
        account_name = simpledialog.askstring("Generate/Add Password", "Enter the account name (e.g., Gmail, Facebook):")
        if not account_name:
            return

        passwords = load_passwords(username)
        if account_name in passwords:
            messagebox.showerror("Error", "Account already exists!")
            return

        # Ask the user if they want to generate a password
        use_generator = messagebox.askyesno("Password Generator", "Would you like to generate a secure password?")
        if use_generator:
            length = simpledialog.askinteger("Password Generator", "Enter the desired password length (e.g., 12):", minvalue=4)
            if not length:
                return
            password = generate_password(length)
            messagebox.showinfo("Generated Password", f"Generated password: {password}")
        else:
            password = simpledialog.askstring("Generate/Add Password", "Enter your password:")
            if not password:
                return

        encrypted_password = encrypt_password(password, encryption_key)
        passwords[account_name] = encrypted_password.decode()
        save_passwords(username, passwords)
        messagebox.showinfo("Success", f"Password for {account_name} saved successfully!")

    def retrieve_password():
        account_name = simpledialog.askstring("Retrieve Password", "Enter the account name:")
        passwords = load_passwords(username)
        if account_name not in passwords:
            messagebox.showerror("Error", "Account not found!")
            return

        encrypted_password = passwords[account_name]
        decrypted_password = decrypt_password(encrypted_password.encode(), encryption_key)
        messagebox.showinfo("Retrieved Password", f"Password for {account_name}: {decrypted_password}")

    def delete_password():
        account_name = simpledialog.askstring("Delete Password", "Enter the account name:")
        passwords = load_passwords(username)
        if account_name not in passwords:
            messagebox.showerror("Error", "Account not found!")
            return

        del passwords[account_name]
        save_passwords(username, passwords)
        messagebox.showinfo("Success", f"Password for {account_name} deleted successfully!")

    def list_passwords():
        passwords = load_passwords(username)
        accounts = "\n".join(passwords.keys()) if passwords else "No accounts saved."
        messagebox.showinfo("Saved Accounts", accounts)

    # Create a single main window (fixing extra window issue)
    manager_window = tk.Tk()  # Change Toplevel to Tk
    manager_window.title(f"Password Manager - {username}")
    manager_window.geometry("500x400")  # Expanded size
    manager_window.configure(bg="#2c3e50")

    tk.Label(manager_window, text=f"Welcome, {username}!", font=("Arial", 18, "bold"), fg="white", bg="#2c3e50").pack(pady=20)

    button_style = {"font": ("Arial", 14), "bg": "#34495e", "fg": "white", "width": 25, "padx": 5, "pady": 5}

    tk.Button(manager_window, text="Generate/Add Password", command=add_password, **button_style).pack(pady=10)
    tk.Button(manager_window, text="Retrieve Password", command=retrieve_password, **button_style).pack(pady=10)
    tk.Button(manager_window, text="Delete Password", command=delete_password, **button_style).pack(pady=10)
    tk.Button(manager_window, text="List Accounts", command=list_passwords, **button_style).pack(pady=10)
    tk.Button(manager_window, text="Exit", command=manager_window.destroy, **button_style).pack(pady=10)

    manager_window.mainloop()

# Main GUI
def login_register_gui():
    def login():
        username = entryName.get()
        master_password = entryPassword.get()

        if not user_exists(username):
            messagebox.showerror("Error", "User does not exist!")
            return

        if not verify_master_password(username, master_password):
            messagebox.showerror("Error", "Incorrect master password!")
            return

        encryption_key = load_key(username)
        root.destroy()  # Close login window
        password_manager(username, encryption_key)

    def register():
        username = entryName.get().strip()
        master_password = entryPassword.get().strip()

        if not username or not master_password:
            messagebox.showerror("Error", "Both username and password are required!")
            return

        if user_exists(username):
            messagebox.showerror("Error", "Username already exists!")
            return

        save_master_password(username, master_password)
        encryption_key = Fernet.generate_key()
        save_key(username, encryption_key)

        os.makedirs(USER_DATA_DIR, exist_ok=True)
        messagebox.showinfo("Success", f"User {username} registered successfully!")

    root = tk.Tk()
    root.title("Password Manager")
    root.geometry("560x270")
    root.configure(bg="#1abc9c")

    # Username Label and Entry
    labelName = tk.Label(root, text="Username:", font=("Arial", 12, "bold"), bg="#1abc9c", fg="white")
    labelName.grid(row=0, column=0, padx=15, pady=15, sticky="e")
    entryName = tk.Entry(root, font=("Arial", 12))
    entryName.grid(row=0, column=1, padx=15, pady=15, sticky="w")

    # Password Label and Entry
    labelPassword = tk.Label(root, text="Password:", font=("Arial", 12, "bold"), bg="#1abc9c", fg="white")
    labelPassword.grid(row=1, column=0, padx=15, pady=15, sticky="e")
    entryPassword = tk.Entry(root, font=("Arial", 12), show="*")
    entryPassword.grid(row=1, column=1, padx=15, pady=15, sticky="w")

    # Buttons
    button_style = {"font": ("Arial", 12, "bold"), "bg": "#16a085", "fg": "white", "padx": 5, "pady": 5}

    buttonLogin = tk.Button(root, text="Login", command=login, **button_style)
    buttonLogin.grid(row=2, column=0, padx=15, pady=10, sticky="we")

    buttonRegister = tk.Button(root, text="Register", command=register, **button_style)
    buttonRegister.grid(row=2, column=1, padx=15, pady=10, sticky="we")

    root.mainloop()

if __name__ == "__main__":
    os.makedirs(USER_DATA_DIR, exist_ok=True)
    login_register_gui()
