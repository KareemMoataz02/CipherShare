import os
import secrets
import json
from typing import Optional



from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import Hash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# File where the symmetric encryption key is stored
KEY_FILE = "symmetric.key"
CREDENTIALS_FILE = "credentials.json"

def generate_symmetric_key() -> bytes:
    """Generate a new 256-bit AES key."""
    return secrets.token_bytes(32)


def save_symmetric_key(key: bytes, path: str = KEY_FILE) -> None:
    """Save the AES key to a file."""
    with open(path, "wb") as f:
        f.write(key)


def load_symmetric_key(path: str = KEY_FILE) -> bytes:
    """Load the AES key from file."""
    with open(path, "rb") as f:
        return f.read()


def get_symmetric_key(path: str = KEY_FILE) -> bytes:
    """
    Retrieve the AES key, generating and saving a new one if it doesn't exist.
    """
    if os.path.exists(path):
        return load_symmetric_key(path)
    key = generate_symmetric_key()
    save_symmetric_key(key, path)
    return key


def hash_password(password: str, salt: bytes = None) -> (bytes, bytes):
    """
    Hash a password with PBKDF2-HMAC-SHA256. Returns (hash, salt).
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    hashed = kdf.derive(password.encode("utf-8"))
    return hashed, salt


def verify_password(password: str, hashed_password: bytes, salt: bytes) -> bool:
    """
    Verify a password against its PBKDF2 hash. Returns True if valid.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode("utf-8"), hashed_password)
        return True
    except Exception:
        return False


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit key from a password using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))


def hash_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of bytes and return hex digest."""
    digest = Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize().hex()


def hash_file(path: str) -> str:
    """Compute SHA-256 hash of a file and return hex digest."""
    digest = Hash(hashes.SHA256(), backend=default_backend())
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            digest.update(chunk)
    return digest.finalize().hex()


def encrypt_bytes(data: bytes, key: bytes) -> (bytes, bytes):
    """
    Encrypt data using AES-CBC with PKCS7 padding. Returns (iv, ciphertext).
    """
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext


def decrypt_bytes(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-CBC encrypted data with PKCS7 padding. Returns plaintext.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def save_encrypted_credentials(token: str, password: str, salt: bytes) -> None:
    """
    Encrypts and stores the session token using a key derived from password and salt.
    """
    key = derive_key_from_password(password, salt)
    iv, ciphertext = encrypt_bytes(token.encode(), key)
    payload = {
        "salt": salt.hex(),
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex()
    }
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(payload, f, indent=4)


def load_encrypted_credentials(password: str) -> Optional[str]:
    """
    Decrypts and returns the session token using the password. Returns None if failed.
    """
    if not os.path.exists(CREDENTIALS_FILE):
        return None
    with open(CREDENTIALS_FILE, "r") as f:
        data = json.load(f)
    try:
        salt = bytes.fromhex(data["salt"])
        iv = bytes.fromhex(data["iv"])
        ciphertext = bytes.fromhex(data["ciphertext"])
        key = derive_key_from_password(password, salt)
        token = decrypt_bytes(iv, ciphertext, key).decode()
        return token
    except Exception:
        return None


