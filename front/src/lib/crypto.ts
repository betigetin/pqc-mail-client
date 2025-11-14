import nacl from "tweetnacl";
import { ChaCha20Poly1305 } from "@stablelib/chacha20poly1305";
import { HKDF } from "@stablelib/hkdf";
import { SHA256 } from "@stablelib/sha256";
import { b64e, b64d, utf8e } from "./b64";

export type DeviceKeys = {
  x25519_priv: string; // base64 raw 32 bytes
  x25519_pub: string;  // base64 raw 32 bytes
  ed25519_priv: string;// base64 raw 64 bytes (secret key)
  ed25519_pub: string; // base64 raw 32 bytes
};

// --- Key generation & storage ---
export function generateDeviceKeys(): DeviceKeys {
  // X25519 priv: 32 random bytes; pub = scalarMult.base(priv)
  const x_priv = nacl.randomBytes(32);
  const x_pub = nacl.scalarMult.base(x_priv);
  
  // Ed25519 sign
  const ed = nacl.sign.keyPair();
  
  return {
    x25519_priv: b64e(x_priv),
    x25519_pub: b64e(x_pub),
    ed25519_priv: b64e(ed.secretKey),
    ed25519_pub: b64e(ed.publicKey),
  };
}

// Persist / load keys in localStorage
export function saveDeviceKeys(keys: DeviceKeys) {
  localStorage.setItem("deviceKeys", JSON.stringify(keys));
}

export function loadDeviceKeys(): DeviceKeys | null {
  const s = localStorage.getItem("deviceKeys");
  return s ? (JSON.parse(s) as DeviceKeys) : null;
}

// --- Derivations ---
export function hkdfSha256(inputKey: Uint8Array, info: Uint8Array, len = 32) {
  const hkdf = new HKDF(SHA256, inputKey);
  return hkdf.expand(len, info);
}

export function deriveAeadKey(shared: Uint8Array, info = utf8e("stegmail-demo")) {
  return hkdfSha256(shared, info, 32);
}

export function deriveMacKey(shared: Uint8Array, info = utf8e("stegmail-mac")) {
  return hkdfSha256(shared, info, 32);
}

// --- AEAD (ChaCha20-Poly1305) ---
export function aeadEncrypt(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array) {
  const aead = new ChaCha20Poly1305(key);
  const nonce = nacl.randomBytes(12);
  const ct = aead.seal(nonce, plaintext, aad);
  return { nonce, ciphertext: ct };
}

export function aeadDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad?: Uint8Array) {
  const aead = new ChaCha20Poly1305(key);
  const pt = aead.open(nonce, ciphertext, aad);
  if (!pt) throw new Error("AEAD decrypt failed");
  return pt;
}

// --- HMAC-SHA256 (WebCrypto) ---
export async function hmacSha256(key: Uint8Array, data: Uint8Array) {
  const k = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", k, data);
  return new Uint8Array(sig);
}

// --- Ed25519 sign/verify ---
export function edSign(secretKey_b64: string, msg: Uint8Array) {
  const sk = b64d(secretKey_b64); // 64 bytes
  const sig = nacl.sign.detached(msg, sk);
  return sig;
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
