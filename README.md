# Password Manager

A secure, user-friendly password manager built with Python and Tkinter. This application allows users to register, securely store, retrieve, delete, and list passwords for various accounts. 

## Features

- **User Registration & Login**: Each user has a unique master password.
- **Password Encryption**: All passwords are encrypted using the `cryptography` module.
- **Password Generator**: Automatically generate secure passwords or input custom passwords.
- **Password Management**: Add, retrieve, delete, and list saved passwords.
- **Interactive GUI**: Designed with Tkinter for an intuitive interface.

## Technologies Used

- **Python 3.9+**
- **Tkinter**: GUI framework for Python.
- **Cryptography**: Ensures secure encryption of passwords.
- **bcrypt**: Hashing for master passwords.

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/Zalay21/PasswordManager.git
   cd PasswordManager

2. Install the required Python modules:
    ```bash
    pip install cryptography bcrypt

3. Run the application:
    ```bash
    python password_generator.py


Usage

1. Register a New User:

    • Enter a username and password, then click "Register."

    • A new account will be created, and all your data will be stored securely.

2. Login:

    • Enter your username and master password, then click "Login."

    • Access your personal password manager dashboard.

3. Password Manager Dashboard:

    • Generate/Add Password: Add new accounts with a generated secure password or a custom password.

    • Retrieve Password: View the stored password for a specific account.

    • Delete Password: Remove an account's password from storage.

    • List Accounts: View all stored accounts.

    • Exit: Close the application.

Folder Structure

    • password_generator.py: The main application script.
    • user_data/: Stores user-specific encrypted keys, master password hashes, and account-password mappings.
    • <username>_key.key: Encryption key for the user.
    • <username>_master.hash: Hashed master password.
    • <username>_passwords.json: Encrypted password storage for the user.

Security

    • Encryption: Uses AES encryption from the cryptography module to secure stored passwords.
    • Hashing: Master passwords are hashed with bcrypt for secure authentication.

Future Enhancements

    • Add multi-factor authentication (MFA) for login.
    • Provide export and import functionality for passwords.
    • Include a dark mode for the GUI.

Contributions

    Contributions are welcome! Feel free to submit a pull request or raise an issue on the repository.

