# ratchet.py
from dataclasses import dataclass
from typing import Optional, Tuple
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# ---------- KDF helpers ----------
def hkdf(ikm: bytes, info: bytes, length: int = 32, salt: Optional[bytes] = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)

def kdf_rk(root_key: bytes, data: bytes) -> Tuple[bytes, bytes]:
    """
    Derive (new_root_key, new_chain_key) from current root_key and some shared data.
    For this demo we use sender's DH public key bytes as 'data' so both sides can
    recompute the same value deterministically from the header.
    """
    material = hkdf(root_key + data, b"rk", length=64)
    return material[:32], material[32:]

def kdf_ck(chain_key: bytes) -> Tuple[bytes, bytes]:
    """
    Derive (message_key, next_chain_key) from current chain_key.
    """
    material = hkdf(chain_key, b"ck", length=64)
    return material[:32], material[32:]


# ---------- Header ----------
@dataclass
class Header:
    """
    Header sent with each message.
      - dh_pub: sender's current DH ratchet public key (bytes)
      - pn: previous sending chain length (unused by this demo, kept for shape)
      - n: message number in current sending chain
      - nonce: 12-byte AEAD nonce
    """
    dh_pub: bytes
    pn: int
    n: int
    nonce: bytes

    def to_dict(self):
        import base64
        return {
            "dh_pub": base64.b64encode(self.dh_pub).decode(),
            "pn": self.pn,
            "n": self.n,
            "nonce": base64.b64encode(self.nonce).decode(),
        }

    @staticmethod
    def from_dict(d):
        import base64
        return Header(
            dh_pub=base64.b64decode(d["dh_pub"]),
            pn=int(d["pn"]),
            n=int(d["n"]),
            nonce=base64.b64decode(d["nonce"]),
        )


# ---------- Simple (in-order) Double Ratchet for demo ----------
class SimpleDoubleRatchet:
    """
    Minimal, in-order "double ratchet"-style demo:

    - Both parties start with the same root_key_seed (e.g., X25519 shared secret, optionally + Kyber secret).
    - The first sending chain key CKs is derived from RK and the SENDER'S dh_pub bytes.
      The receiver derives CKr from RK and that same dh_pub carried in the header.
    - On receiving a *new* sender dh_pub, the receiver "ratchets": recompute RK & CKr using that dh_pub.
    - ChaCha20-Poly1305 AEAD with random 12-byte nonces per message.

    Notes:
    * This is a didactic simplification suitable for your demo. It does not fully match the Signal spec,
      and it does not implement skipped-message key storage or out-of-order receipt handling.
    """

    def __init__(
        self,
        is_initiator: bool,
        root_key_seed: bytes,
        my_dh_priv: Optional[X25519PrivateKey] = None,
        their_dh_pub: Optional[bytes] = None,   # kept for API symmetry; unused in the demo KDF
    ):
        self.is_initiator = is_initiator

        # Root key derived from shared seed
        self.RK = hkdf(root_key_seed, b"root-key", length=32)

        # Our current DH ratchet private key
        self.DHs = my_dh_priv or X25519PrivateKey.generate()

        # Last remote dh_pub we processed (bytes)
        self.last_remote_dh: Optional[bytes] = None

        # Chain keys & counters
        self.CKs: Optional[bytes] = None  # sending chain
        self.CKr: Optional[bytes] = None  # receiving chain
        self.Ns = 0                       # msg number in current sending chain
        self.Nr = 0                       # msg number in current receiving chain
        self.PN = 0                       # previous sending chain length (not used here)

    # -- internal helpers --

    def _my_dh_pub_bytes(self) -> bytes:
        return self.DHs.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def _ratchet_on_receive(self, their_pub_bytes: bytes):
        """
        "Ratchet" on receipt of a message with a DH public key we haven't seen before.
        For the demo, RK' and CKr are derived deterministically from RK and that their_pub_bytes.
        """
        # If this is a brand new remote DH, advance RK and create a fresh receiving chain
        if (self.last_remote_dh is None) or (self.last_remote_dh != their_pub_bytes):
            self.PN = self.Ns
            self.Ns = 0
            self.Nr = 0
            self.last_remote_dh = their_pub_bytes
            self.RK, self.CKr = kdf_rk(self.RK, their_pub_bytes)

    # -- public API --

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> tuple[Header, bytes]:
        """
        Returns (Header, ciphertext). The header includes our current dh_pub and a random AEAD nonce.
        On the first send (or after we rotate our DH), we deterministically derive CKs from RK and *our* dh_pub,
        so the receiver can mirror it from the header.
        """
        if self.CKs is None:
            # First send (or after a local DH rotation): bind sending chain to our current dh_pub
            dh_pub_bytes = self._my_dh_pub_bytes()
            self.RK, self.CKs = kdf_rk(self.RK, dh_pub_bytes)

        mk, self.CKs = kdf_ck(self.CKs)
        self.Ns += 1

        nonce = os.urandom(12)
        ct = ChaCha20Poly1305(mk).encrypt(nonce, plaintext, aad)

        hdr = Header(
            dh_pub=self._my_dh_pub_bytes(),
            pn=self.PN,
            n=self.Ns - 1,
            nonce=nonce,
        )
        return hdr, ct

    def decrypt(self, header: Header, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """
        In-order decryption. If header.dh_pub is new, "ratchet" the receiving chain from RK and that dh_pub.
        Then advance CKr to derive the message key and decrypt.
        """
        # Ratchet on new remote DH pub
        self._ratchet_on_receive(header.dh_pub)

        if self.CKr is None:
            # If for any reason CKr is missing (shouldn't happen in-order),
            # derive it again deterministically from RK and last_remote_dh.
            self.RK, self.CKr = kdf_rk(self.RK, self.last_remote_dh)

        mk, self.CKr = kdf_ck(self.CKr)
        self.Nr += 1

        pt = ChaCha20Poly1305(mk).decrypt(header.nonce, ciphertext, aad)
        return pt

    def my_public_key(self) -> bytes:
        return self._my_dh_pub_bytes()

