"""
client_demo_jwt_mac3.py

Demonstrates:
 - JWT-based login (token)
 - Uploading device pubkeys (X25519/Ed25519/PQC)
 - Sending five messages:
    1) Non-repudiable: Ed25519 signature
    2) Repudiable: HMAC-SHA256 (MAC)
    3) Hybrid: X25519 + Kyber768 (liboqs)
    4-5) Double Ratchet (forward secrecy & post-compromise security)
 - Bob fetches inbox and verifies/decrypts.

Run:
    python client_demo_jwt_mac3.py
"""
import os, time, hmac, json, base64, hashlib, requests
from pathlib import Path
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder

import oqs
from ratchet import SimpleDoubleRatchet, Header  # requires ratchet.py in project

API_BASE = "http://127.0.0.1:5000/api"

# ---------------- helpers ----------------
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def b64enc(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64dec(s: str) -> bytes:
    return base64.b64decode(s.encode()) if s else b""


def derive_aead_key(shared_secret: bytes, info: bytes = b"stegmail-demo") -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared_secret)

def derive_mac_key(shared_secret: bytes, info: bytes = b"stegmail-mac") -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared_secret)

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> (bytes, bytes):
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    return nonce, aead.encrypt(nonce, plaintext, aad)

def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


def ensure_keys_for_user(prefix: str):
    """Persist X25519 + Ed25519 per user under ./keys.
    Returns:
      x25519_priv (X25519PrivateKey),
      x25519_pub_raw (bytes),
      ed25519_sign_sk (SigningKey),
      ed25519_pub_raw (bytes)
    """
    os.makedirs("keys", exist_ok=True)
    x_priv_file = f"keys/{prefix}_x25519_priv.raw"
    x_pub_file  = f"keys/{prefix}_x25519_pub.raw"
    ed_priv_file = f"keys/{prefix}_ed25519_priv.raw"
    ed_pub_file  = f"keys/{prefix}_ed25519_pub.raw"

    if os.path.exists(x_priv_file) and os.path.exists(x_pub_file):
        xpriv_raw = open(x_priv_file, "rb").read()
        xpub_raw  = open(x_pub_file,  "rb").read()
        xpriv = X25519PrivateKey.from_private_bytes(xpriv_raw)
    else:
        xpriv = X25519PrivateKey.generate()
        xpriv_raw = xpriv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        xpub_raw = xpriv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        open(x_priv_file, "wb").write(xpriv_raw)
        open(x_pub_file,  "wb").write(xpub_raw)

    if os.path.exists(ed_priv_file) and os.path.exists(ed_pub_file):
        ed_priv_raw = open(ed_priv_file, "rb").read()
        ed_pub_raw  = open(ed_pub_file,  "rb").read()
        sign_sk = SigningKey(ed_priv_raw, encoder=RawEncoder)
    else:
        sign_sk = SigningKey.generate()
        ed_priv_raw = sign_sk.encode(encoder=RawEncoder)
        ed_pub_raw  = sign_sk.verify_key.encode(encoder=RawEncoder)
        open(ed_priv_file, "wb").write(ed_priv_raw)
        open(ed_pub_file,  "wb").write(ed_pub_raw)

    return xpriv, xpub_raw, sign_sk, ed_pub_raw


def compute_hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, digestmod=hashlib.sha256).digest()


# ---------------- server wrappers ----------------
def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}

def login(email: str, password: str) -> str:
    r = requests.post(f"{API_BASE}/login", json={"email": email, "password": password})
    r.raise_for_status()
    return r.json()["token"]

def upload_device_keys(device_id: str, device_pubkeys: dict, token: str):
    r = requests.post(
        f"{API_BASE}/keys/upload",
        json={"device_id": device_id, "device_pubkeys": device_pubkeys},
        headers=auth_headers(token),
    )
    r.raise_for_status()
    return r.json()

def fetch_keys(email_hash: str):
    r = requests.get(f"{API_BASE}/keys/{email_hash}")
    r.raise_for_status()
    return r.json()

def send_message(to_hash: str, from_hash: str, payload: dict, token: str):
    r = requests.post(
        f"{API_BASE}/messages/send",
        json={"to_user_hash": to_hash, "from_user_hash": from_hash, "payload": payload},
        headers=auth_headers(token),
    )
    if r.status_code != 201:
        print("[!] Server rejected message:", r.status_code, r.text)
        return None
    return r.json()

def fetch_inbox(token: str):
    r = requests.post(f"{API_BASE}/messages/inbox", json={}, headers=auth_headers(token))
    r.raise_for_status()
    return r.json()

def save_inbox_to_file(history):
    out = Path("data/inbox_bob.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    prev = {"messages": []}
    if out.exists():
        try:
            prev = json.load(open(out, "r"))
        except Exception:
            prev = {"messages": []}
    msgs = {m["id"]: m for m in prev.get("messages", [])}
    for m in history:
        msgs[m["id"]] = m
    json.dump(
        {"saved_at": datetime.now(timezone.utc).isoformat(), "messages": list(msgs.values())},
        open(out, "w"),
        indent=2,
    )
    print("[*] Saved inbox to", out)


# ---------------- demo ----------------
def demo():
    print("[*] JWT + MAC demo starting. Server:", API_BASE)
    alice_email, alice_pw = "alice@example.com", "alicepass"
    bob_email,   bob_pw   = "bob@example.com",   "bobpass"

    # tolerant register
    def reg(email, pw):
        try:
            r = requests.post(f"{API_BASE}/register", json={"email": email, "password": pw})
            if r.status_code in (200, 201):
                return r.json()
        except Exception:
            pass
        return {"email_hash": sha256_hex(email)}

    print("[*] Registering users (tolerant)...")
    a_reg, b_reg = reg(alice_email, alice_pw), reg(bob_email, bob_pw)
    a_hash, b_hash = a_reg["email_hash"], b_reg["email_hash"]
    print("  alice:", a_hash)
    print("  bob  :", b_hash)

    # login -> tokens
    print("[*] Logging in to obtain tokens...")
    a_tok = login(alice_email, alice_pw)
    b_tok = login(bob_email,   bob_pw)
    print("  alice token len:", len(a_tok))
    print("  bob token len:  ", len(b_tok))

    # persistent classical keys
    print("[*] Loading or generating keypairs for Alice & Bob...")
    a_priv, a_pub_raw, a_sign_sk, a_sign_pk = ensure_keys_for_user("alice")
    b_priv, b_pub_raw, b_sign_sk, b_sign_pk = ensure_keys_for_user("bob")
    b_pub = X25519PublicKey.from_public_bytes(b_pub_raw)

    # PQC KEM contexts (keep alive until Bob decapsulates)
    kem_a = oqs.KeyEncapsulation("Kyber768")
    a_pqc_pub = kem_a.generate_keypair()
    kem_b = oqs.KeyEncapsulation("Kyber768")
    b_pqc_pub = kem_b.generate_keypair()

    # Upload device keys
    upload_device_keys("alice-web-01", {
        "x25519": b64enc(a_pub_raw),
        "ed25519": b64enc(a_sign_pk),
        "pqc_kem": "Kyber768",
        "pqc_pubkey": b64enc(a_pqc_pub),
    }, a_tok)
    upload_device_keys("bob-web-01", {
        "x25519": b64enc(b_pub_raw),
        "ed25519": b64enc(b_sign_pk),
        "pqc_kem": "Kyber768",
        "pqc_pubkey": b64enc(b_pqc_pub),
    }, b_tok)
    print("  uploaded device keys (with JWT & PQC)")

    # Fetch Bob’s public keys
    b_keys = fetch_keys(b_hash)
    b_dev0 = b_keys["devices"][0]["device_pubkeys"]
    b_x_raw = b64dec(b_dev0["x25519"])
    b_x_pub = X25519PublicKey.from_public_bytes(b_x_raw)
    b_pqc_bytes = b64dec(b_dev0.get("pqc_pubkey", "")) if b_dev0.get("pqc_pubkey") else None

    # ----- Message 1: Ed25519 -----
    print("[*] Preparing Message 1 (Ed25519 signed)...")
    eph1 = X25519PrivateKey.generate()
    eph1_pub = eph1.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    ss1 = eph1.exchange(b_x_pub)
    key1 = derive_aead_key(ss1)
    n1, ct1 = aead_encrypt(key1, b"Hello Bob - msg1 (signed)", aad=b"v1")
    msg1_to_sign = eph1_pub + n1 + ct1 + b"v1"
    sig1 = a_sign_sk.sign(msg1_to_sign).signature
    send_message(b_hash, a_hash, {
        "version": "1",
        "handshake": {"ephemeral_x25519_pub": b64enc(eph1_pub)},
        "from_device_id": "alice-web-01",
        "aad": b64enc(b"v1"),
        "nonce": b64enc(n1),
        "ciphertext": b64enc(ct1),
        "signature": b64enc(sig1),
        "sig_alg": "ed25519"
    }, a_tok)
    print("  sent message 1 (ed25519)")

    # ----- Message 2: MAC -----
    print("[*] Preparing Message 2 (MAC-based)...")
    eph2 = X25519PrivateKey.generate()
    eph2_pub = eph2.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    ss2 = eph2.exchange(b_x_pub)
    key2 = derive_aead_key(ss2)
    n2, ct2 = aead_encrypt(key2, b"Hello Bob - msg2 (MAC)", aad=b"v1")
    mac = compute_hmac_sha256(derive_mac_key(ss2), eph2_pub + n2 + ct2 + b"v1")
    send_message(b_hash, a_hash, {
        "version": "1",
        "handshake": {"ephemeral_x25519_pub": b64enc(eph2_pub)},
        "from_device_id": "alice-web-01",
        "aad": b64enc(b"v1"),
        "nonce": b64enc(n2),
        "ciphertext": b64enc(ct2),
        "signature": b64enc(mac),
        "sig_alg": "mac"
    }, a_tok)
    print("  sent message 2 (mac)")

    # ----- Message 3: Hybrid -----
    print("[*] Preparing Message 3 (Hybrid PQC + X25519)...")
    eph3 = X25519PrivateKey.generate()
    eph3_pub = eph3.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    ssx = eph3.exchange(b_x_pub)
    if not b_pqc_bytes:
        raise RuntimeError("Bob device lacks pqc_pubkey")
    ct_pqc, ss_pqc_sender = kem_a.encap_secret(b_pqc_bytes)
    hy_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hybrid-session-key").derive(ssx + ss_pqc_sender)
    n3 = os.urandom(12)
    ct3 = ChaCha20Poly1305(hy_key).encrypt(n3, b"Hello Bob - msg3 (Hybrid PQC+X25519)", b"hybrid-v1")
    send_message(b_hash, a_hash, {
        "version": "1",
        "handshake": {"ephemeral_x25519_pub": b64enc(eph3_pub)},
        "from_device_id": "alice-web-01",
        "aad": b64enc(b"hybrid-v1"),
        "nonce": b64enc(n3),
        "ciphertext": b64enc(ct3),
        "pqc_kem_alg": "Kyber768",
        "pqc_ct": b64enc(ct_pqc),
        "sig_alg": "hybrid"
    }, a_tok)
    print("  sent message 3 (hybrid)")

    # ----- Messages 4 & 5: Double Ratchet -----
    print("[*] Preparing Messages 4 & 5 (Double Ratchet)...")
    # Bootstrap with a static X25519 secret (demo only)
    bootstrap_ss = a_priv.exchange(b_x_pub)

    dr_alice = SimpleDoubleRatchet(
        is_initiator=True,
        root_key_seed=bootstrap_ss,
        my_dh_priv=X25519PrivateKey.generate(),
        their_dh_pub=b_x_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
    )

    # msg4
    h4, ct4 = dr_alice.encrypt(b"Hello Bob - msg4 (Double Ratchet)", aad=b"dr-v1")
    send_message(b_hash, a_hash, {
        "version": "1",
        "sig_alg": "dr",
        "from_device_id": "alice-web-01",
        "handshake": {"dr_header": Header.to_dict(h4)},
        "aad": b64enc(b"dr-v1"),
        "nonce": b64enc(h4.nonce),
        "ciphertext": b64enc(ct4),
    }, a_tok)
    print("  sent message 4 (double ratchet)")

    # msg5
    h5, ct5 = dr_alice.encrypt(b"Hello Bob - msg5 (Double Ratchet again)", aad=b"dr-v1")
    send_message(b_hash, a_hash, {
        "version": "1",
        "sig_alg": "dr",
        "from_device_id": "alice-web-01",
        "handshake": {"dr_header": Header.to_dict(h5)},
        "aad": b64enc(b"dr-v1"),
        "nonce": b64enc(h5.nonce),
        "ciphertext": b64enc(ct5),
    }, a_tok)
    print("  sent message 5 (double ratchet)")

    time.sleep(1)

    # ----- Bob fetches -----
    print("[*] Bob fetching inbox...")
    inbox = fetch_inbox(b_tok)
    messages = sorted(inbox.get("messages", []), key=lambda m: m["id"])
    hist = []

    # ---- Prepare Bob's Double Ratchet once ----
    # Derive same bootstrap secret Alice used (X25519 static-static in this demo)
    a_pub = X25519PublicKey.from_public_bytes(a_pub_raw)
    bootstrap_ss_bob = b_priv.exchange(a_pub)

    # Find the FIRST DR header from Alice (to initialize Bob's ratchet)
    first_dr_header = None
    for m in messages:
        p = m.get("payload", {})
        if p.get("sig_alg") == "dr":
            hdr_dict = p.get("handshake", {}).get("dr_header") or p.get("dr_header")
            if hdr_dict:
                first_dr_header = Header.from_dict(hdr_dict)
                break

    dr_bob = None
    if first_dr_header:
        dr_bob = SimpleDoubleRatchet(
            is_initiator=False,
            root_key_seed=bootstrap_ss_bob,
            their_dh_pub=first_dr_header.dh_pub
        )

    # ---- Process inbox ----
    for m in messages:
        print("----")
        print("Message id:", m["id"], "from:", m["from"])
        p = m["payload"]
        sig_alg = p.get("sig_alg", "ed25519")
        aad = b64dec(p.get("aad", "")) if p.get("aad") else b""
        ct = b64dec(p.get("ciphertext", ""))

        decrypted_text = None

        if sig_alg in ("ed25519", "mac", "hybrid"):
            eph_b64 = p.get("handshake", {}).get("ephemeral_x25519_pub", "")
            eph = b64dec(eph_b64) if eph_b64 else None
            if not eph:
                print("  [!] Missing ephemeral X25519 pub")
                hist.append({"id": m["id"], "from": m["from"], "sig_alg": sig_alg, "decrypted_text": "<not decrypted>"})
                continue
            nonce = b64dec(p.get("nonce", ""))
            eph_pub = X25519PublicKey.from_public_bytes(eph)
            ss = b_priv.exchange(eph_pub)

            if sig_alg == "ed25519":
                sig = b64dec(p.get("signature", ""))
                # Recreate exactly what Alice signed:
                msg_to_verify = eph + nonce + ct + aad
                sender_keys = fetch_keys(m["from"])
                devs = sender_keys.get("devices", [])
                dev = next((d for d in devs if d.get("device_pubkeys", {}).get("ed25519")), None)
                if dev:
                    try:
                        vk = VerifyKey(b64dec(dev["device_pubkeys"]["ed25519"]), encoder=RawEncoder)
                        # Verify message with detached signature
                        vk.verify(msg_to_verify, sig)
                        print("  Signature OK")
                        key = derive_aead_key(ss)
                        decrypted_text = aead_decrypt(key, nonce, ct, aad).decode()
                        print("   Decrypted:", decrypted_text)
                    except Exception as e:
                        print("  Signature FAIL:", e)
                else:
                    print("  No sender ed25519 pubkey; cannot verify")

            elif sig_alg == "mac":
                sig = b64dec(p.get("signature", ""))
                if hmac.compare_digest(compute_hmac_sha256(derive_mac_key(ss), eph + nonce + ct + aad), sig):
                    print("  MAC OK")
                    key = derive_aead_key(ss)
                    decrypted_text = aead_decrypt(key, nonce, ct, aad).decode()
                    print("   Decrypted:", decrypted_text)
                else:
                    print("  MAC FAIL")

            elif sig_alg == "hybrid":
                pqc_ct = b64dec(p.get("pqc_ct", ""))
                try:
                    ss_pqc_recv = kem_b.decap_secret(pqc_ct)
                    hy_key_bob = HKDF(
                        algorithm=hashes.SHA256(), length=32, salt=None, info=b"hybrid-session-key"
                    ).derive(ss + ss_pqc_recv)
                    decrypted_text = ChaCha20Poly1305(hy_key_bob).decrypt(b64dec(p["nonce"]), ct, aad).decode()
                    print("  Hybrid OK")
                    print("   Decrypted:", decrypted_text)
                except Exception as e:
                    print("  Hybrid FAIL:", e)

        elif sig_alg == "dr":
            if dr_bob is None:
                print("  DR FAIL: no ratchet initialised")
            else:
                try:
                    hdr_dict = p.get("handshake", {}).get("dr_header") or p.get("dr_header")
                    hdr = Header.from_dict(hdr_dict)
                    decrypted_text = dr_bob.decrypt(hdr, ct, aad).decode()
                    print("  DR OK")
                    print("   Decrypted:", decrypted_text)
                except Exception as e:
                    print("  DR FAIL:", e)

        else:
            print("  Unknown sig_alg:", sig_alg)

        hist.append({
            "id": m["id"],
            "from": m["from"],
            "sig_alg": sig_alg,
            "decrypted_text": decrypted_text or "<not decrypted>",
        })

    save_inbox_to_file(hist)


if __name__ == "__main__":
    demo()

