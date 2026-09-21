#!/usr/bin/env python3
import os, sys, base64, struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#names of files where keys will be stored
PRIV_PATH = "private_key.pem"
PUB_PATH  = "public_key.pem"

AES_KEY_SIZE   = 32  # 256-bit AES key - which is 32 BYTES (256 bits / 8 bits per byte = 32 bytes)
AES_NONCE_SIZE = 12  # 96-bit nonce, standard for GCM - which is 12 BYTES (96 bits / 8 bits per byte = 12 bytes)

def keys():
    #Generate 2048-bit RSA private key
    if os.path.exists(PRIV_PATH) and os.path.exists(PUB_PATH):
        print(f"\nKey files {PRIV_PATH} and {PUB_PATH} already exist. Delete them first if you want to regenerate keys.")
        return

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    #save priv key to pem file
        #encoding -> serialization.Encoding.PEM means store in PEM format
        #format -> serialization.PrivateFormat.PKCS8 means store in PKCS#8 format
        #encryptionAlgo -> NoEncryption() means store unencrypted
    with open(PRIV_PATH, "wb") as file:
        file.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))

     #save public key to pem file
        # encoding -> serialization.Encoding.PEM means store in PEM format
        # format -> serialization.PublicFormat.SubjectPublicKeyInfo means store in X.509 SubjectPublicKeyInfo format (STANDARD)
    with open(PUB_PATH, "wb") as file:
        file.write(priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"✓ created {PRIV_PATH}\n✓ created {PUB_PATH}\n")

# 
def rsa_encrypt(plain_bytes: bytes) -> bytes:
    #store public key in variable
    pub = serialization.load_pem_public_key(open(PUB_PATH, "rb").read())

    #.encrypt takes param (plaintext and padding)
    #use OAEP padding with SHA-256 to keep message secure
    #mgf=padding.MGF1(hashes.SHA256()) means use SHA-256 for the mask generation function
    #algorithm=hashes.SHA256() means use SHA-256 for the hash function
    #label=None means no label is used
    return pub.encrypt(plain_bytes, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(cipher_bytes: bytes) -> bytes:

    priv = serialization.load_pem_private_key(open(PRIV_PATH, "rb").read(), password=None)

    return priv.decrypt(cipher_bytes, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ENCRYPT key with RSA-OAEP, encrypt message with AES-GCM, and package everything together
def encrypt(plain_bytes: bytes) -> bytes:
    """
    Hybrid encryption:
      1. Generate a random one-time AES-256 key + nonce.
      2. Encrypt the actual message with AES-GCM (fast, handles any length,
         and gives us authentication/tamper-detection for free via the tag).
      3. Encrypt that AES key with RSA-OAEP (using the public key).
      4. Package everything together so decrypt() can pull it back apart:
         [4-byte length of RSA-encrypted key][RSA-encrypted key][nonce][AES ciphertext+tag]
    """

    aesKey = AESGCM.generate_key(bit_length=AES_KEY_SIZE * 8) # generate a random AES key with 256 bits (32 bytes)
    nonce = os.urandom(AES_NONCE_SIZE) # generate a random nonce with 96 bits (12 bytes)

    # this is essentially saying I want to use aesy key in GCM mode:
     # create an AESGCM object with the generated AES key 
     # GCM is a mode of operation for symmetric key cryptographic block ciphers and is needed for AES-GCM encryption
    aesgcm = AESGCM(aesKey)
    aes_ciphertext = aesgcm.encrypt(nonce, plain_bytes, None)  # encrypt the plaintext with AES-GCM, using the nonce and no additional authenticated data (AAD)

    encrypted_aes_key = rsa_encrypt(aesKey) # encrypt the AES key with RSA-OAEP using the public key BECAUSE the AES key is a one-time key and needs to be kept secret

    # prefix the encrypted key with its length so decrypt() knows where it ends
    # struct.pack(">I", len(encrypted_aes_key)) is used to pack the length of the RSA-encrypted AES key as a 4-byte unsigned integer in big-endian format. 
    # then add the encrypted AES key, nonce, and AES ciphertext to the packed data
    #this produces a single byte string that contains all the necessary information for decryption CREATING SOMETHING LIKE -->  [sizeof][encrypted AES key][nonce][ciphertext]

    key_length = len(encrypted_aes_key) #size of the RSA-encrypted AES key in bytes (2048 bits / 8 bits per byte = 256 bytes) this part is used incase you switch to a different RSA key size in the future so you don't have to change the code
    packed = struct.pack(">I", key_length) + encrypted_aes_key + nonce + aes_ciphertext
    return packed

# Decrypt the given ciphertext bytes
def decrypt(cipher_bytes: bytes) -> bytes:
    """
    Reverses encrypt():
      1. Read the length-prefixed RSA-encrypted AES key and RSA-decrypt it.
      2. Pull out the nonce.
      3. Whatever remains is the AES-GCM ciphertext (+ tag); decrypt/verify it.
    """
    # unpack reads first 4 bytes of cipher_bytes as a big-endian unsigned intege --> gives you length of the RSA-encrypted AES key
    # unpack always returns tuple so retrieve [0] gets the first element of the tuple returned by struct.unpack
    key_length = struct.unpack(">I", cipher_bytes[:4])[0]
    pointer = 4 # start reading after the 4-byte length prefix

    encrypted_aes_key = cipher_bytes[pointer:pointer + key_length] # slice the cipher_bytes to get the RSA-encrypted AES key which would be everything after the first 4 bytes up to the length of the RSA-encrypted AES key (hardcoded would be ****encrypted_aes_key = cipher_bytes[:256]***)
    pointer += key_length # move the pointer forward by the length of the RSA-encrypted AES key so that now the next pieces are [sizeof][encrypted AES key] -POINTER IS HERE- [nonce][ciphertext]

    nonce = cipher_bytes[pointer:pointer + AES_NONCE_SIZE] # nonce is from current pointer position to the next 12 bytes (AES_NONCE_SIZE) which is the nonce used for AES-GCM encryption
    pointer += AES_NONCE_SIZE # now move pointer to the end of the nonce so that now the next pieces are [sizeof][encrypted AES key][nonce] -POINTER IS HERE- [ciphertext]

    aes_ciphertext = cipher_bytes[pointer:] #ciphertext is everything after the nonce (pointer already moved to end of nonce so anything after that is the AES-GCM ciphertext )

    aes_key = rsa_decrypt(encrypted_aes_key) # decrypt the RSA-encrypted AES key using the private key

    aesgcm = AESGCM(aes_key) # create an AESGCM object with the decrypted AES key to be used for decryption
    return aesgcm.decrypt(nonce, aes_ciphertext, None)  # decrypt the AES-GCM ciphertext using the nonce and no additional authenticated data (AAD) and return the plaintext bytes


def main():

    #generate keys
    keys()

    print("\n Hybrid RSA + AES Encryption / Decryption ")
    # Encrypt
    msg = input("Input message to encrypt: ") # ask user for input
    encrypted_msg = encrypt(msg.encode("utf-8")) # Encode msg (text -> plaintext bytes) and then encrypt the message (plaintext bytes -> ciphertext bytes)
    ct_b64 = base64.b64encode(encrypted_msg).decode("ascii") # encode the ciphertext bytes into base64 (actual text "ascii") to be used to copy and paste later for decryption
    print("\nEncrypted version (Base64): " + ct_b64) # print the base64 encoded ciphertext to the user so they can copy and paste it for decryption

    # Decrypt
    print("\nNow Decryption Time!")

    # keep repeating until the user inputs a valid Base64 ciphertext or chooses to quit
    while True:
        # 1. Ask for a new plaintext message/input to encrypt or 'q' to quit
        msg = input("\nEnter a message to encrypt (or 'q' to quit): ").strip()

        #if they press q, exit the program
        if msg.lower() == "q":
            print("Exiting program...")
            break

        # 2. Encrypt the message
        #encrypt using AES-GCM and RSA-OAEP hybrid encryption, which returns ciphertext bytes
        encrypted_msg = encrypt(msg.encode("utf-8"))

        # 3. Convert encrypted bytes to Base64
        # take the ciphertext bytes and encode them into Base64 format, then decode it to ASCII string for easy copy-pasting
        ct_b64 = base64.b64encode(encrypted_msg).decode("ascii")

        print("\nEncrypted version (Base64):")
        print(ct_b64)

        # 4. Ask user to paste Base64 back in
        b64_input = input("\nPaste the Base64 ciphertext to decrypt: ").strip()

        # try is used to catch any exceptions that may occur during the decryption process, such as invalid Base64 input or decryption errors
        try:
            # 5. Convert Base64 back to ciphertext bytes
            ct_bytes = base64.b64decode(b64_input, validate=True)

            # 6. Decrypt
            # decrypt the ciphertext bytes back to plaintext bytes using the hybrid decryption function
            plaintext = decrypt(ct_bytes).decode("utf-8")

            print("\nDecrypted message:", plaintext)

        except Exception as e:
            print("\nCould not decrypt.")
            print(f"Error details: {e}")

if __name__ == "__main__":
    main()