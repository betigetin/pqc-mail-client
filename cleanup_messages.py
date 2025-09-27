# cleanup_messages.py
"""
Scan messages in the dev DB and delete messages whose Ed25519 signature
cannot be verified using the sender's registered device ed25519 public key.

Usage (venv active):
    python cleanup_messages.py

Backups: make sure to backup stegmail_dev.db before running.
"""
import json, base64
from backend import create_app, db
from backend.models import Message, Device, User
from nacl.signing import VerifyKey
from nacl.encoding import RawEncoder

def b64dec(s):
    return base64.b64decode(s.encode()) if s else b""

def find_ed25519_for_sender(sender_hash, from_device_id):
    user = User.query.filter_by(email_hash=sender_hash).first()
    if not user:
        return None
    devs = Device.query.filter_by(user_id=user.id).all()
    # prefer device with matching device_id and ed25519
    for d in devs:
        if d.device_id == from_device_id:
            try:
                pubkeys = json.loads(d.device_pubkeys)
                ed = pubkeys.get("ed25519")
                if ed:
                    return base64.b64decode(ed)
            except Exception:
                continue
    # fallback: any device with ed25519
    for d in devs:
        try:
            pubkeys = json.loads(d.device_pubkeys)
            ed = pubkeys.get("ed25519")
            if ed:
                return base64.b64decode(ed)
        except Exception:
            continue
    return None

def verify_message(msg):
    """
    Return True if OK, False if verification fails or cannot be verified.
    Only handles sig_alg == 'ed25519'. For other sig_alg values, returns True
    to avoid deleting mac messages.
    """
    try:
        payload = json.loads(msg.payload)
    except Exception:
        return False

    sig_alg = payload.get("sig_alg", "ed25519")
    if sig_alg != "ed25519":
        # don't delete MAC messages (server can't verify)
        return True

    # Extract fields
    handshake = payload.get("handshake", {})
    eph_b64 = handshake.get("ephemeral_x25519_pub", "")
    nonce_b64 = payload.get("nonce", "")
    ciphertext_b64 = payload.get("ciphertext", "")
    aad_b64 = payload.get("aad", "")
    sig_b64 = payload.get("signature", "")
    from_device_id = payload.get("from_device_id", "")

    eph_raw = b64dec(eph_b64)
    nonce_raw = b64dec(nonce_b64)
    ciphertext_raw = b64dec(ciphertext_b64)
    aad_raw = b64dec(aad_b64) if aad_b64 else b""
    signature_raw = b64dec(sig_b64) if sig_b64 else b""

    if not signature_raw:
        return False

    # find ed25519 pubkey from sender device
    sender_hash = msg.from_user_hash
    ed_pub_raw = find_ed25519_for_sender(sender_hash, from_device_id)
    if not ed_pub_raw:
        # no ed25519 found -> consider invalid (or you may choose to keep)
        return False

    verify_input = eph_raw + nonce_raw + ciphertext_raw + aad_raw
    signed_combo = signature_raw + verify_input
    try:
        vk = VerifyKey(ed_pub_raw, encoder=RawEncoder)
        vk.verify(signed_combo)
        return True
    except Exception:
        return False

def main():
    app = create_app()
    with app.app_context():
        msgs = Message.query.order_by(Message.created_at.asc()).all()
        to_delete = []
        ok = []
        for m in msgs:
            result = verify_message(m)
            if not result:
                to_delete.append(m.id)
            else:
                ok.append(m.id)

        print("Total messages:", len(msgs))
        print("Valid messages (kept):", len(ok))
        print("Invalid messages (to delete):", len(to_delete))
        if not to_delete:
            print("No messages to delete.")
            return

        print("IDs to delete:", to_delete)
        confirm = input("Proceed to DELETE these messages? Type 'yes' to proceed: ")
        if confirm.strip().lower() != "yes":
            print("Aborted. No changes made.")
            return

        # Delete
        for mid in to_delete:
            m = Message.query.get(mid)
            if m:
                db.session.delete(m)
        db.session.commit()
        print("Deleted", len(to_delete), "messages.")

if __name__ == "__main__":
    main()
