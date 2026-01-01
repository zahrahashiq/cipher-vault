# Cipher Vault

My cipher vault is a local-only password vault that is built with Python and Flask.
This project shows secure storage, encryption workflow, and session based access control (rather than a production ready password manager).
This was built as a learning-based security application.

## Disclaimer
This is a local project created for learning purposes.
Please do not store real or sensitive password in Cipher Vault.

## Why this project exists
The goal of making the cipher vault was to explore the following:
- how passwords can be transformed into encryption keys securely.
- how to accessing sensitive data (login details) can be gated, timed and revoked.
- how to use frontend design to minimise accidental exposure of sensitive info.
- how encrypted data can be stored securely on a disk

This is **NOT** supposed to replace real password managers but to show how they're structured internally on a smaller scale.

## What the cipher vault does
- Allows the user to create a vault that is protected by a master password.
- Derives a symmetric encryption key from the master password using Argon2id.
- Uses AES-GCM to encrypt the vault contents.
- Stores the encrypted vault as vault.enc (Git ignores this)
- Keeps the encryption key on server memory only - never in cookies or files.
- Automatically locks the vault after 300 seconds of inactivity.
- Temporary password reveal - automatically hides the passwords after 10 seconds of inactivity.
- Fetches passwords on demand so they're not rendered in HTML.
- Allows copying the passwords to clipboard with feedback to the user


## Security Design

### Argon2id - Key derivation
- The master password is processed with Argon2id. This is a memory hard KDF.
- It makes brute-force attacks significantly more expensive than faster hashes.
- The KDF params and salt are stored alongside the vault so the key can be re-derived safely.

### AES-GCM - Encryption
- The info in the vault is encrypted using AES-GCM.
- This makes the info confidential and gives them tamper detection.
- Each save generates a new random nonce.

### Session-based access
- A random session token is stored in the flask session when the vault is unlocked.
- The derived encryption key is stored server-side only and is mapped to that token.
- The keys are removed when logged out, timeout or the server restarting.
- API endpoints return "401" instead of HTML redirecting to the frontend.

### Minimising exposure in the UI
- The passwords are fetched on demand and never embedded in the page HTML.
- The passwords are fetched one by one via an API only when requested.
- Revealed passwords auto-hide after a period of time.

## What the cipher vault doesn't do
There are some features that have been avoided as they would be needed for a real world password manager.
- Cloud sync or remote storage
- Multi-user support
- Password strength analysis, breach checking
- Protection from a compromised local machine

## Future Improvements
- Adding vault format validation and version migration
- Supporting vault ex/import
- Adding password generation

## Runing crypto vault
```bash
python app.py