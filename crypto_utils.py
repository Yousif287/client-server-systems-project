"""
Utility functions for cryptographic operations used in the secure chat project.
Provides RSA key generation, RSA encryption/decryption, AES key generation, 
AES encryption/decryption with CBC mode and Base64 encoding.

Functions:
- generate_rsa_keypair
- encrypt_with_rsa
- decrypt_with_rsa
- generate_aes_key
- encrypt_with_aes
- decrypt_with_aes
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# --- RSA Operations ---

def generate_rsa_keypair():
    """
    Generate a new RSA key pair (2048 bits).
    Returns:
        tuple: (private_key_bytes, public_key_bytes)
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_with_rsa(public_key_bytes, message_bytes):
    """
    Encrypt data using the recipient's RSA public key.

    Args:
        public_key_bytes (bytes): The public RSA key.
        message_bytes (bytes): The message to encrypt.

    Returns:
        bytes: The RSA-encrypted message.
    """
    pub_key = RSA.import_key(public_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    return cipher_rsa.encrypt(message_bytes)

def decrypt_with_rsa(private_key_bytes, encrypted_bytes):
    """
    Decrypt RSA-encrypted data using the private RSA key.

    Args:
        private_key_bytes (bytes): The private RSA key.
        encrypted_bytes (bytes): The encrypted message.

    Returns:
        bytes: The decrypted message.
    """
    priv_key = RSA.import_key(private_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(priv_key)
    return cipher_rsa.decrypt(encrypted_bytes)

# --- AES Operations ---

def generate_aes_key():
    """
    Generate a random AES key (128-bit).

    Returns:
        bytes: The AES key.
    """
    return get_random_bytes(16)  # 128-bit key

def encrypt_with_aes(aes_key, plaintext):
    """
    Encrypt plaintext using AES in CBC mode with a random IV.

    Args:
        aes_key (bytes): The AES encryption key.
        plaintext (str): The plaintext to encrypt.

    Returns:
        str: The Base64 encoded ciphertext (IV + ciphertext).
    """
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_with_aes(aes_key, b64_ciphertext):
    """
    Decrypt AES-encrypted data that was Base64 encoded.

    Args:
        aes_key (bytes): The AES decryption key.
        b64_ciphertext (str): The Base64 encoded ciphertext (IV + ciphertext).

    Returns:
        str: The decrypted plaintext.
    """
    raw = base64.b64decode(b64_ciphertext)
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()