# backend/crypto_utils.py
import hashlib
from argon2 import PasswordHasher
from nacl.signing import SigningKey
from nacl.public import PrivateKey
from nacl.encoding import Base64Encoder

ph = PasswordHasher()

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(hash_pw: str, password: str) -> bool:
    try:
        return ph.verify(hash_pw, password)
    except Exception:
        return False

def generate_x25519_keypair_base64():
    sk = PrivateKey.generate()
    pk = sk.public_key
    return sk.encode(encoder=Base64Encoder).decode(), pk.encode(encoder=Base64Encoder).decode()

def generate_ed25519_keypair_base64():
    sk = SigningKey.generate()
    pk = sk.verify_key
    return sk.encode(encoder=Base64Encoder).decode(), pk.encode(encoder=Base64Encoder).decode()
