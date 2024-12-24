# Password Manager

A secure and user-friendly password manager built with Python. It uses encryption to securely store and manage user passwords, offering features like password generation, retrieval, and deletion.

## Features

- **Secure Password Storage**: Stores passwords encrypted using `cryptography`'s `Fernet` encryption.
- **Password Generation**: Generates strong, random passwords with customizable lengths.
- **GUI Support**: Easy-to-use interface for adding, retrieving, and managing passwords (built with Tkinter).
- **User Authentication**: Supports user registration and login with hashed master passwords (`bcrypt`).
- **Account Management**: Add, retrieve, delete, or list all saved accounts.

## Prerequisites

- Python 3.8 or higher
- Required Python libraries:
  - `cryptography`
  - `bcrypt`
  - `tkinter` (comes pre-installed with Python)
  - `json`
  - `os`

Install dependencies using:
```bash
pip install cryptography bcrypt
```

## Usage

1. Clone the repository:
```bash
git clone https://github.com/your-username/Password-Manager.git
cd Password-Manager
```

2. Run the program:
```bash
python password_generator.py
```

3. Follow the GUI prompts to:
   - Register a new account.
   - Log in to an existing account.
   - Generate, add, retrieve, delete, or list saved passwords.

## Example Workflow

1. **Registration**:
   - Enter a unique username and master password.
   - The program generates an encryption key and stores it securely.

2. **Login**:
   - Use the registered username and master password to log in.

3. **Password Management**:
   - Generate or add passwords for various accounts.
   - Retrieve saved passwords securely.
   - Delete accounts or view a list of all saved accounts.

## Future Enhancements

- Add support for cloud storage (e.g., AWS, Google Drive) for syncing passwords.
- Implement multi-factor authentication for added security.
- Enhance the GUI for better user experience.
