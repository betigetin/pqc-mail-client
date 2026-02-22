import nacl from "tweetnacl";
import { ChaCha20Poly1305 } from "@stablelib/chacha20poly1305";
import { HKDF } from "@stablelib/hkdf";
import { SHA256 } from "@stablelib/sha256";
import { b64e, b64d, utf8e } from "./b64";
import { Kyber768 } from "./kyber_lib";

export type DeviceKeys = {
  x25519_priv: string;
  x25519_pub: string;
  ed25519_priv: string;
  ed25519_pub: string;
  kyber_priv: string;
  kyber_pub: string;
};

export async function generateDeviceKeys(): Promise<DeviceKeys> {
  const x_priv = nacl.randomBytes(32);
  const x_pub = nacl.scalarMult.base(x_priv);
  const ed = nacl.sign.keyPair();

  const kyber = new Kyber768(); 
  const [pk, sk] = await kyber.generateKeyPair(); 
  
  return {
    x25519_priv: b64e(x_priv),
    x25519_pub: b64e(x_pub),
    ed25519_priv: b64e(ed.secretKey),
    ed25519_pub: b64e(ed.publicKey),
    kyber_priv: b64e(sk),
    kyber_pub: b64e(pk),
  };
}

export function saveDeviceKeys(keys: DeviceKeys) {
  localStorage.setItem("deviceKeys", JSON.stringify(keys));
}

export function loadDeviceKeys(): DeviceKeys | null {
  const s = localStorage.getItem("deviceKeys");
  return s ? (JSON.parse(s) as DeviceKeys) : null;
}

export function hkdfSha256(inputKey: Uint8Array, info: Uint8Array, len = 32) {
  const hkdf = new HKDF(SHA256, inputKey);
  return hkdf.expand(len, info);
}

export function deriveAeadKey(shared: Uint8Array, info = utf8e("latticemail-aead")) {
  return hkdfSha256(shared, info, 32);
}

export function deriveMacKey(shared: Uint8Array, info = utf8e("latticemail-mac")) {
  return hkdfSha256(shared, info, 32);
}

/**
 * HYBRID DERIVATION LOGIC
 */
export function deriveHybridSecret(
  x25519_shared: Uint8Array,
  kyber_shared: Uint8Array,
): Uint8Array {
  const combined = new Uint8Array(x25519_shared.length + kyber_shared.length);
  combined.set(x25519_shared);
  combined.set(kyber_shared, x25519_shared.length);

  const salt = utf8e("Latticemail-v1-Salt");
  const info = utf8e("Hybrid-ML-KEM-X25519-KEX");
  
  const hkdf = new HKDF(SHA256, combined, salt);
  return hkdf.expand(32, info);
}

// --- AEAD (ChaCha20-Poly1305) - THIS WAS MISSING ---
export function aeadEncrypt(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array) {
  const aead = new ChaCha20Poly1305(key);
  const nonce = nacl.randomBytes(12);
  const ct = aead.seal(nonce, plaintext, aad);
  return { nonce, ciphertext: ct };
}

export function aeadDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad?: Uint8Array) {
  const aead = new ChaCha20Poly1305(key);
  const pt = aead.open(nonce, ciphertext, aad);
  if (!pt) throw new Error("AEAD decrypt failed (PQ-Security Breach or Corrupt Data)");
  return pt;
}

// --- HMAC-SHA256 ---
export async function hmacSha256(key: Uint8Array, data: Uint8Array) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, data);
  return new Uint8Array(sig);
}

// --- Ed25519 ---
export function edSign(secretKey_b64: string, msg: Uint8Array) {
  const sk = b64d(secretKey_b64);
  return nacl.sign.detached(msg, sk);
}

export function edVerify(publicKey_b64: string, msg: Uint8Array, sig: Uint8Array) {
  const pk = b64d(publicKey_b64);
  return nacl.sign.detached.verify(msg, sig, pk);
}

// --- X25519 DH ---
export function x25519Shared(myPriv_b64: string, theirPub_b64: string) {
  const my = b64d(myPriv_b64);
  const th = b64d(theirPub_b64);
  return nacl.scalarMult(my, th);
}
