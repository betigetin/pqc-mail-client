# # backend/models.py
# from backend import db
# from datetime import datetime

# class User(db.Model):
#     __tablename__ = 'users'
#     id = db.Column(db.Integer, primary_key=True)
#     email_hash = db.Column(db.String(64), unique=True, nullable=False)
#     password_hash = db.Column(db.String(255), nullable=False)
#     primary_pubkeys = db.Column(db.Text)  # JSON string for primary pubkeys
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)

# class Device(db.Model):
#     __tablename__ = 'devices'
#     id = db.Column(db.Integer, primary_key=True)
#     device_id = db.Column(db.String(128), nullable=False)
#     user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     device_pubkeys = db.Column(db.Text)  # JSON string for device pubkeys
#     encrypted_bundle = db.Column(db.LargeBinary, nullable=True)
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)

# class Message(db.Model):
#     __tablename__ = 'messages'
#     id = db.Column(db.Integer, primary_key=True)
#     to_user_hash = db.Column(db.String(64), nullable=False)
#     from_user_hash = db.Column(db.String(64), nullable=False)
#     payload = db.Column(db.Text, nullable=False)  # JSON envelope string
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)












# backend/models.py
from backend import db
from datetime import datetime


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email_hash = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    primary_pubkeys = db.Column(db.Text)  # JSON string for primary pubkeys
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(128), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    device_pubkeys = db.Column(db.Text)  # JSON string for device pubkeys (x25519, ed25519, etc.)
    encrypted_bundle = db.Column(db.LargeBinary, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ➕ NEW FIELDS for Post-Quantum / Hybrid keys
    pqc_kem_alg = db.Column(db.String, nullable=True)   # e.g. "Kyber768"
    pqc_pubkey = db.Column(db.Text, nullable=True)      # base64 encoded PQC public key


class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    to_user_hash = db.Column(db.String(64), nullable=False)
    from_user_hash = db.Column(db.String(64), nullable=False)
    payload = db.Column(db.Text, nullable=False)  # JSON envelope string
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ➕ NEW FIELDS for Post-Quantum / Hybrid messages
    pqc_kem_alg = db.Column(db.String, nullable=True)   # algorithm used (e.g. Kyber768)
    pqc_ct = db.Column(db.Text, nullable=True)          # base64-encoded PQC ciphertext
