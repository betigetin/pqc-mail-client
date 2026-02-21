// front/src/lib/crypto.ts
import nacl from "tweetnacl";
import { ChaCha20Poly1305 } from "@stablelib/chacha20poly1305";
import { HKDF } from "@stablelib/hkdf";
import { SHA256 } from "@stablelib/sha256";
import { b64e, b64d, utf8e } from "./b64";
import { Kyber768 } from "./kyber_lib";

// ... [DeviceKeys type and generateDeviceKeys remain the same] ...

/**
 * HYBRID DERIVATION LOGIC
 * This is the critical "Defense in Depth" layer.
 * We use HKDF to compress the entropy from both classical and quantum secrets.
 */
export function deriveHybridSecret(
  x25519_shared: Uint8Array,
  kyber_shared: Uint8Array,
): Uint8Array {
  // Pattern: Hash(Classical || Quantum)
  // This prevents an attacker from being able to manipulate the output
  // even if they compromise one of the two primitive secrets.
  const combined = new Uint8Array(x25519_shared.length + kyber_shared.length);
  combined.set(x25519_shared);
  combined.set(kyber_shared, x25519_shared.length);

  // We use a specific 'salt' and 'info' string to tie this key 
  // to the Latticemail Hybrid Key Exchange (KEX) context.
  const salt = utf8e("Latticemail-v1-Salt");
  const info = utf8e("Hybrid-ML-KEM-X25519-KEX");
  
  const hkdf = new HKDF(SHA256, combined, salt);
  return hkdf.expand(32, info);
}

// ... [AEAD and Signature functions remain the same] ...
