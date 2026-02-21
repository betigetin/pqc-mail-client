import React, { useState } from "react";
import { useAuth } from "../state/auth";
import { api } from "../lib/api";
import { Kyber768 } from "../lib/kyber_lib";
import {
  loadDeviceKeys,
  deriveAeadKey,
  aeadEncrypt,
  edSign,
  deriveMacKey,
  hmacSha256,
  deriveHybridSecret, // <--- MAKE SURE THIS IS IMPORTED
} from "../lib/crypto";
import { b64e, b64d, utf8e } from "../lib/b64";
import { sha256Hex } from "../lib/hash";

export function Compose() {
  const { token } = useAuth();
  const [toEmail, setToEmail] = useState("bob@example.com");
  const [fromEmail, setFromEmail] = useState("alice@example.com");
  const [msg, setMsg] = useState("Hello from the web UI!");
  const [alg, setAlg] = useState<"ed25519" | "mac">("mac");

  const [info, setInfo] = useState<string>("");
  const [sending, setSending] = useState(false);

  async function onSend(e: React.FormEvent) {
    e.preventDefault();
    setInfo("");
    if (!token) {
      setInfo("Login required.");
      return;
    }
    const keys = loadDeviceKeys();
    if (!keys) {
      setInfo("Generate + upload your device keys first.");
      return;
    }

    // --- DELETED THE BAD CODE BLOCK THAT WAS HERE ---

    setSending(true);
    try {
      // derive recipient keys
      const toHash = await sha256Hex(toEmail);
      const fromHash = await sha256Hex(fromEmail);
      const toKeys = await api.fetchKeysByHash(toHash);

      const preferredDeviceId = "web-01";
      const toDeviceEntry =
        toKeys?.devices?.find((d: any) => d.device_id === preferredDeviceId) ||
        toKeys?.devices?.[0];
      const dev0 = toDeviceEntry?.device_pubkeys;

      if (!dev0?.x25519) {
        setInfo("Recipient has no x25519 pubkey uploaded.");
        return;
      }

      // --- START HYBRID ENCRYPTION LOGIC ---

      // 1. Classical Shared Secret (X25519)
      const nacl = (await import("tweetnacl")).default;
      const ephPriv = nacl.randomBytes(32);
      const ephPub = nacl.scalarMult.base(ephPriv);
      const recipientX25519 = b64d(dev0.x25519);
      const ss_classic = nacl.scalarMult(ephPriv, recipientX25519);

      // 2. Post-Quantum Shared Secret (Kyber-768)
      if (!dev0.kyber_pub) {
        throw new Error(
          "Recipient missing Kyber key. Cannot send PQC message.",
        );
      }
      const recipientKyberPub = b64d(dev0.kyber_pub);

      const sender = new Kyber768();
      // Encap returns [ciphertext, sharedSecret]
      const [kyber_ciphertext_raw, ss_pq_raw] =
        await sender.encap(recipientKyberPub);

      const ss_pq = ss_pq_raw;
      const kyber_ciphertext = kyber_ciphertext_raw;

      // 3. MIX THEM (The Hybrid Root Key)
      const hybridRootKey = deriveHybridSecret(ss_classic, ss_pq);
      const key = deriveAeadKey(hybridRootKey); // Use this key to encrypt

      // 4. Encrypt Message
      const aad = utf8e("v1");
      const { nonce, ciphertext } = aeadEncrypt(key, utf8e(msg), aad);

      // 5. Sign (Optional)
      let signature: string | undefined;
      let sig_alg = alg;

      if (alg === "ed25519") {
        const bytesToSign = new Uint8Array([
          ...ephPub,
          ...nonce,
          ...ciphertext,
          ...aad,
        ]);
        const sig = edSign(keys.ed25519_priv, bytesToSign);
        signature = b64e(sig);
      } else if (alg === "mac") {
        const macKey = deriveMacKey(hybridRootKey);
        const mac = await hmacSha256(
          macKey,
          new Uint8Array([...ephPub, ...nonce, ...ciphertext, ...aad]),
        );
        signature = b64e(mac);
      }

      // 6. Construct Payload
      const payload = {
        version: "1",
        from_device_id: "web-01",
        sig_alg,
        handshake: {
          ephemeral_x25519_pub: b64e(ephPub),
          kyber_ciphertext: b64e(kyber_ciphertext), // PQC Payload
        },
        aad: b64e(aad),
        nonce: b64e(nonce),
        ciphertext: b64e(ciphertext),
        ...(signature ? { signature } : {}),
      };

      // --- END HYBRID LOGIC ---

      await api.sendMessage(toHash, fromHash, payload, token);
      setInfo("Message sent successfully!");
      setMsg("");
    } catch (e: any) {
      setInfo(`Failed: ${e?.message ?? String(e)}`);
    } finally {
      setSending(false);
    }
  }

  return (
    <div
      className="app-container"
      style={{
        minHeight: "calc(100vh - 100px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "2rem",
      }}
    >
      <div
        style={{
          maxWidth: "600px",
          width: "100%",
          background: "var(--color-surface)",
          borderRadius: "1.25rem",
          padding: "2.5rem",
          boxShadow:
            "0 20px 60px rgba(0, 0, 0, 0.4), 0 0 1px rgba(34, 211, 238, 0.1)",
          border: "1px solid rgba(255, 255, 255, 0.05)",
        }}
      >
        <div style={{ marginBottom: "2rem" }}>
          <h1
            style={{
              fontSize: "1.75rem",
              fontWeight: "600",
              marginBottom: "0.5rem",
              color: "var(--color-text)",
            }}
          >
            Compose Message
          </h1>

          <p
            style={{
              fontSize: "0.95rem",
              color: "var(--color-muted)",
              lineHeight: "1.5",
            }}
          >
            Send an end-to-end encrypted message with quantum-safe cryptography
          </p>
        </div>

        <form
          onSubmit={onSend}
          style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}
        >
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "1rem",
            }}
          >
            <div>
              <label
                style={{
                  fontSize: "0.875rem",
                  color: "var(--color-muted)",
                  display: "block",
                  marginBottom: "0.5rem",
                  fontWeight: "500",
                }}
              >
                From
              </label>
              <input
                className="input"
                value={fromEmail}
                onChange={(e) => setFromEmail(e.target.value)}
                placeholder="your@email.com"
                type="email"
                required
                style={{
                  fontSize: "0.9rem",
                  padding: "0.7rem 0.9rem",
                }}
              />
            </div>

            <div>
              <label
                style={{
                  fontSize: "0.875rem",
                  color: "var(--color-muted)",
                  display: "block",
                  marginBottom: "0.5rem",
                  fontWeight: "500",
                }}
              >
                To
              </label>
              <input
                className="input"
                value={toEmail}
                onChange={(e) => setToEmail(e.target.value)}
                placeholder="recipient@email.com"
                type="email"
                required
                style={{
                  fontSize: "0.9rem",
                  padding: "0.7rem 0.9rem",
                }}
              />
            </div>
          </div>

          <div>
            <label
              style={{
                fontSize: "0.875rem",
                color: "var(--color-muted)",
                display: "block",
                marginBottom: "0.5rem",
                fontWeight: "500",
              }}
            >
              Message
            </label>
            <textarea
              className="input"
              value={msg}
              onChange={(e) => setMsg(e.target.value)}
              placeholder="Write your encrypted message here..."
              required
              style={{
                width: "100%",
                minHeight: "160px",
                fontSize: "0.95rem",
                padding: "0.85rem 1rem",
                resize: "vertical",
                fontFamily: "inherit",
                lineHeight: "1.6",
              }}
            />
          </div>

          <div
            style={{
              padding: "1.25rem",
              background: "rgba(255, 255, 255, 0.02)",
              borderRadius: "0.75rem",
              border: "1px solid rgba(255, 255, 255, 0.05)",
            }}
          >
            <label
              style={{
                fontSize: "0.875rem",
                color: "var(--color-muted)",
                display: "block",
                marginBottom: "0.75rem",
                fontWeight: "500",
              }}
            >
              Signature Algorithm
            </label>

            <div style={{ display: "flex", gap: "1.5rem", flexWrap: "wrap" }}>
              <label
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.5rem",
                  cursor: "pointer",
                  fontSize: "0.9rem",
                  color: "var(--color-text)",
                }}
              >
                <input
                  type="radio"
                  name="alg"
                  checked={alg === "ed25519"}
                  onChange={() => setAlg("ed25519")}
                  style={{ accentColor: "var(--color-accent)" }}
                />
                <span>Ed25519 (Signed)</span>
              </label>

              <label
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.5rem",
                  cursor: "pointer",
                  fontSize: "0.9rem",
                  color: "var(--color-text)",
                }}
              >
                <input
                  type="radio"
                  name="alg"
                  checked={alg === "mac"}
                  onChange={() => setAlg("mac")}
                  style={{ accentColor: "var(--color-accent)" }}
                />
                <span>MAC (Repudiable)</span>
              </label>
            </div>

            <p
              style={{
                fontSize: "0.8rem",
                color: "var(--color-muted)",
                marginTop: "0.75rem",
                fontStyle: "italic",
              }}
            >
              Hybrid/Double Ratchet: Active (X25519 + Kyber-768)
            </p>
          </div>

          {info && (
            <div
              style={{
                padding: "0.85rem 1.1rem",
                background: info.startsWith("Failed")
                  ? "rgba(239, 68, 68, 0.1)"
                  : "rgba(34, 211, 238, 0.1)",
                border: info.startsWith("Failed")
                  ? "1px solid rgba(239, 68, 68, 0.3)"
                  : "1px solid rgba(34, 211, 238, 0.3)",
                borderRadius: "0.5rem",
                color: info.startsWith("Failed") ? "#fca5a5" : "#22D3EE",
                fontSize: "0.9rem",
                display: "flex",
                alignItems: "center",
                gap: "0.5rem",
              }}
            >
              <span>{info.startsWith("Failed") ? "⚠️" : "✓"}</span>
              <span>{info}</span>
            </div>
          )}

          <div
            style={{
              display: "flex",
              gap: "1rem",
              paddingTop: "0.5rem",
            }}
          >
            <button
              className="btn-primary"
              type="submit"
              disabled={sending}
              style={{
                flex: 1,
                padding: "0.85rem",
                fontSize: "1rem",
                fontWeight: "600",
                opacity: sending ? 0.7 : 1,
                cursor: sending ? "not-allowed" : "pointer",
              }}
            >
              {sending ? "Encrypting & Sending..." : "Send Encrypted Message"}
            </button>

            <button
              type="button"
              className="btn-ghost"
              onClick={() => {
                setMsg("");
                setInfo("");
              }}
              disabled={sending}
              style={{
                padding: "0.85rem 1.25rem",
                fontSize: "0.95rem",
              }}
            >
              Clear
            </button>
          </div>
        </form>

        <div
          style={{
            marginTop: "1.5rem",
            paddingTop: "1.5rem",
            borderTop: "1px solid rgba(255, 255, 255, 0.05)",
            fontSize: "0.8rem",
            color: "var(--color-muted)",
            textAlign: "center",
            lineHeight: "1.5",
          }}
        >
          Messages are encrypted using Hybrid Post-Quantum Cryptography (X25519
          + Kyber-768)
        </div>
      </div>
    </div>
  );
}

