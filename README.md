# RSA Key Generation & Encryption

A simple Python project that:
- Generates an RSA key pair (`private_key.pem`, `public_key.pem`)
- Encrypts with the public key, decrypts with the private key

## Setup (use a virtual environment)
macOS / Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography
```

Windows (PowerShell):
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install cryptography
```

## Run
```bash
python rsa.py
```
What happens:
1. Keys are created if not already generated
2. You enter a message → it prints a Base64 ciphertext.
3. Paste a Base64 ciphertext → it tries to decrypt and prints the plaintext.


