# upload_alice_keys.py
import base64, requests
from nacl.signing import SigningKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

API_BASE = "http://127.0.0.1:5000/api"

def b64enc(b): return base64.b64encode(b).decode()

# generate (or reuse) keys - here we generate new volatile keys for test
xpriv = X25519PrivateKey.generate()
xpub_raw = xpriv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

sign_sk = SigningKey.generate()
sign_vk_raw = sign_sk.verify_key.encode()  # 32 bytes

# Prepare payload (replace email/password with your test creds)
payload = {
    "email": "alice@example.com",
    "password": "AlicePass1!",
    "device_id": "alice-web-01",
    "device_pubkeys": {
        "x25519": b64enc(xpub_raw),
        "ed25519": b64enc(sign_vk_raw)
    }
}

r = requests.post(f"{API_BASE}/keys/upload", json=payload)
print(r.status_code, r.text)
