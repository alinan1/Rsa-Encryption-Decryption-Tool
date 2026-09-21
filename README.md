# Hybrid RSA + AES Encryption

How it works:
- Generates an RSA key pair (private_key.pem, public_key.pem)
- Generates a random one-time AES-256 key for each message
- Encrypts the actual message using AES-GCM
- Uses the RSA public key to encrypt the AES key
- Uses the RSA private key to recover the AES key
- Uses the recovered AES key to decrypt the original message
- Uses Base64 to encode encrypted ciphertext bytes into readable text for easy copying and pasting, then during decryption it decodes the Base64 text back into ciphertext bytes.

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


