#!/usr/bin/env python3
import os, sys, base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

#names of files where keys will be stored
PRIV_PATH = "private_key.pem"
PUB_PATH  = "public_key.pem"

def keys():
    #Generate 2048-bit RSA private key 
    if os.path.exists(PRIV_PATH) and os.path.exists(PUB_PATH):
        print(f"\nKey files {PRIV_PATH} and {PUB_PATH} already exist. Delete them first if you want to regenerate keys.")
        return  

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    #save priv key to pem file
        #encoding ->
        #format ->
        #encryptionAlgo -> NoEncryption() means store unencrypted
    with open(PRIV_PATH, "wb") as file:
        file.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
        
     #save public key to pem file    
    with open(PUB_PATH, "wb") as file:
        file.write(priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"✓ wrote {PRIV_PATH}\n✓ wrote {PUB_PATH}\n")

def encrypt(plain_bytes: bytes) -> bytes:
    #store public key in variable
    pub = serialization.load_pem_public_key(open(PUB_PATH, "rb").read())

    #.encrypt takes param (plaintext and padding )
        #use OAEP padding with SHA-256 to keep message secure
    return pub.encrypt(plain_bytes,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt(cipher_bytes: bytes) -> bytes:
    #store private key in variable
    priv = serialization.load_pem_private_key(open(PRIV_PATH, "rb").read(), password=None)

    #.decrypt takes param (ciphortext and padding )
        #reverses the OAEP(SHA256) padding
    return priv.decrypt(
        cipher_bytes,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def main():

    #generate keys
    keys()

    print("\n/--- RSA Encryption / Decryption Demo ---/")
    # Encrypt 
    msg = input("Input message to encrypt: ") # ask user for input
    encrypted_msg = encrypt(msg.encode("utf-8")) # Encode msg (text -> plaintext bytes) and then encrypt the message (plaintext bytes -> ciphortext bytes)
    ct_b64 = base64.b64encode(encrypted_msg).decode("ascii") # encode the ciphortext bytes into base64 (actual text "ascii") to be used to copy and paste later for decryption
    print("\nEncrypted version (Base64): " + ct_b64)

    # Decrypt 
    print("\nNow Decrypt!!!")

    while True:
        b64_input = input("Paste the Base64 characters (single line, or 'q' to quit): ").strip()
        if b64_input.strip().lower() == "q":
            print("Exiting decryption...")
            break
        try:
            ct_bytes = base64.b64decode(b64_input, validate=True)
            plaintext = decrypt(ct_bytes).decode("utf-8", errors="strict")
            print("\nDecrypted message:", plaintext)
            break
        except Exception as e:
            print("\nCould not decrypt. Make sure you pasted the exact Base64 ciphertext created with the matching keys.")
            print(f"Error details: {e}\n")
            continue  # make the retry explicit

if __name__ == "__main__":
    main()
