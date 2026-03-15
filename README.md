# 🔐 Password Manager

A secure desktop password manager built with Python. Uses **Fernet symmetric encryption** to protect stored credentials and **bcrypt** to hash master passwords — no plaintext secrets ever touch disk.

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat&logo=python&logoColor=white)
![Encryption](https://img.shields.io/badge/Encryption-Fernet%20(AES--128--CBC)-green)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## Features

- **Fernet Encryption** — All passwords are encrypted at rest using the `cryptography` library's Fernet implementation (AES-128-CBC with HMAC-SHA256)
- **Bcrypt Master Password** — Master passwords are salted and hashed with bcrypt; never stored in plaintext
- **Secure Password Generator** — Generates cryptographically random passwords using Python's `secrets` module with configurable length
- **Multi-User Support** — Each user gets their own encryption key, master password hash, and credential store
- **Tkinter GUI** — Clean graphical interface for registration, login, and password management
- **JSON Storage** — Encrypted credentials stored in structured JSON files per user

---

## Project Structure

```
PasswordManager/
├── password_generator.py    # Main application (GUI + crypto logic)
├── user_data/               # Created at runtime
│   ├── <user>_key.key       # Fernet encryption key
│   ├── <user>_master.hash   # Bcrypt-hashed master password
│   └── <user>_passwords.json# Encrypted credential store
└── README.md
```

---

## Installation

**Prerequisites:** Python 3.8+, pip

```bash
# Clone the repository
git clone https://github.com/Zalay21/PasswordManager.git
cd PasswordManager

# Install dependencies
pip install cryptography bcrypt
```

> **Note:** `tkinter` ships with most Python installations. On Debian/Ubuntu, install with: `sudo apt install python3-tk`

---

## Usage

```bash
python password_generator.py
```

### 1. Register a New Account

When the application launches, enter a username and master password, then click **Register**. This creates:
- A unique Fernet encryption key for your vault
- A bcrypt hash of your master password

### 2. Log In

Enter your credentials and click **Login** to access the password manager.

### 3. Manage Passwords

From the main dashboard you can:

| Action | Description |
|--------|-------------|
| **Generate/Add Password** | Create a new entry — choose to auto-generate a secure password or enter your own |
| **Retrieve Password** | Decrypt and view a saved password by account name |
| **Delete Password** | Remove a stored credential |
| **List Accounts** | View all account names in your vault |

### Example: Generating a Password

```
┌─────────────────────────────────┐
│  Enter account name: GitHub     │
│  Generate secure password? [Y]  │
│  Password length: 20            │
│                                 │
│  ✓ Generated: j#9Kx!mP2$vR&... │
│  ✓ Encrypted and saved          │
└─────────────────────────────────┘
```

---

## How It Works

```
Master Password → bcrypt hash → stored in <user>_master.hash
                                (used for authentication only)

Fernet Key → generated once per user → stored in <user>_key.key
          → encrypts/decrypts all passwords in <user>_passwords.json

Stored Password = Fernet(key).encrypt(plaintext_password)
Retrieved Password = Fernet(key).decrypt(stored_ciphertext)
```

---

## Technologies

| Component | Technology |
|-----------|-----------|
| Language | Python 3 |
| Encryption | `cryptography` (Fernet / AES-128-CBC + HMAC-SHA256) |
| Password Hashing | `bcrypt` (salted adaptive hashing) |
| Random Generation | `secrets` (cryptographically secure) |
| GUI | `tkinter` |
| Storage | JSON flat files |

---

## Security Notes

- Encryption keys are stored locally in plaintext — this is a personal-use tool, not an enterprise vault
- For production use, consider wrapping the key file with OS-level protection or a hardware security module
- Master passwords should be strong; bcrypt provides protection against brute-force attacks

---

## Future Enhancements

- [ ] Cloud sync (encrypted backup to remote storage)
- [ ] Multi-factor authentication
- [ ] Password strength meter
- [ ] Auto-lock after inactivity timeout
- [ ] CLI mode for headless environments

---

## Author

**Za Lay** — [GitHub](https://github.com/Zalay21) · [LinkedIn](https://linkedin.com/in/zalay0021) · [zalay0021@gmail.com](mailto:zalay0021@gmail.com)
