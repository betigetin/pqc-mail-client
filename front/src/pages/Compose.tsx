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
  deriveHybridSecret,
} from "../lib/crypto";
import { b64e, b64d, utf8e } from "../lib/b64";
import { sha256Hex } from "../lib/hash";

export function Compose() {
  const { token } = useAuth();
  const [toEmail, setToEmail] = useState("bob@example.com");
  const [fromEmail, setFromEmail] = useState("alice@example.com");
  const [msg, setMsg] = useState("Hello! This message is protected by hybrid post-quantum encryption.");
  const [alg, setAlg] = useState<"ed25519" | "mac">("mac");

  const [info, setInfo] = useState<string>("");
  const [sending, setSending] = useState(false);
  const [cryptoLogs, setCryptoLogs] = useState<string[]>([]);

  async function onSend(e: React.FormEvent) {
    e.preventDefault();
    setInfo("");
    setCryptoLogs(["Initializing Hybrid Handshake..."]);
    
    if (!token) {
      setInfo("Login required.");
      return;
    }
    const keys = loadDeviceKeys();
    if (!keys) {
      setInfo("Generate + upload your device keys first.");
      return;
    }

    setSending(true);
    try {
      const toHash = await sha256Hex(toEmail);
      const fromHash = await sha256Hex(fromEmail);
      
      setCryptoLogs(prev => [...prev, "Fetching Recipient Public Bundle..."]);
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

      // 1. Classical (X25519)
      setCryptoLogs(prev => [...prev, "Generating ephemeral X25519 pair..."]);
      const nacl = (await import("tweetnacl")).default;
      const ephPriv = nacl.randomBytes(32);
      const ephPub = nacl.scalarMult.base(ephPriv);
      const recipientX25519 = b64d(dev0.x25519);
      const ss_classic = nacl.scalarMult(ephPriv, recipientX25519);

      // 2. Post-Quantum (ML-KEM-768)
      if (!dev0.kyber_pub) {
        throw new Error("Recipient missing Kyber/ML-KEM key.");
      }
      setCryptoLogs(prev => [...prev, "Performing ML-KEM-768 Encapsulation..."]);
      const recipientKyberPub = b64d(dev0.kyber_pub);
      const sender = new Kyber768();
      const [kyber_ciphertext_raw, ss_pq_raw] = await sender.encap(recipientKyberPub);

      // 3. MIX THEM (Hybrid Secret Derivation)
      setCryptoLogs(prev => [...prev, "Deriving Hybrid Root Secret via HKDF..."]);
      const hybridRootKey = deriveHybridSecret(ss_classic, ss_pq_raw);
      const key = deriveAeadKey(hybridRootKey);

      // 4. Encrypt Message Body
      setCryptoLogs(prev => [...prev, "Encrypting payload (AES-GCM-SIV)..."]);
      const aad = utf8e("v1");
      const { nonce, ciphertext } = aeadEncrypt(key, utf8e(msg), aad);

      let signature: string | undefined;
      let sig_alg = alg;

      if (alg === "ed25519") {
        setCryptoLogs(prev => [...prev, "Applying Ed25519 Digital Signature..."]);
        const bytesToSign = new Uint8Array([...ephPub, ...nonce, ...ciphertext, ...aad]);
        signature = b64e(edSign(keys.ed25519_priv, bytesToSign));
      } else if (alg === "mac") {
        setCryptoLogs(prev => [...prev, "Computing Deniable HMAC-SHA256..."]);
        const macKey = deriveMacKey(hybridRootKey);
        const mac = await hmacSha256(macKey, new Uint8Array([...ephPub, ...nonce, ...ciphertext, ...aad]));
        signature = b64e(mac);
      }

      const payload = {
        version: "1",
        from_device_id: "web-01",
        sig_alg,
        handshake: {
          ephemeral_x25519_pub: b64e(ephPub),
          kyber_ciphertext: b64e(kyber_ciphertext_raw),
        },
        aad: b64e(aad),
        nonce: b64e(nonce),
        ciphertext: b64e(ciphertext),
        ...(signature ? { signature } : {}),
      };

      await api.sendMessage(toHash, fromHash, payload, token);
      setCryptoLogs(prev => [...prev, "Payload (~1.2KB) dispatched to Blind Relay."]);
      setInfo("Message sent successfully!");
      setMsg("");
    } catch (e: any) {
      setInfo(`Failed: ${e?.message ?? String(e)}`);
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="app-container" style={{ minHeight: "90vh", display: "flex", alignItems: "center", justifyContent: "center", padding: "2rem" }}>
      <div style={{ maxWidth: "700px", width: "100%", background: "var(--color-surface)", borderRadius: "1.25rem", padding: "2.5rem", border: "1px solid rgba(255, 255, 255, 0.05)", position: "relative", boxShadow: "0 20px 50px rgba(0,0,0,0.5)" }}>
        
        {/* PQC Status Badge */}
        <div style={{ position: "absolute", top: "1.5rem", right: "1.5rem", background: "rgba(34, 211, 238, 0.1)", border: "1px solid #22D3EE", color: "#22D3EE", padding: "4px 12px", borderRadius: "100px", fontSize: "0.75rem", fontWeight: "bold", display: "flex", alignItems: "center", gap: "6px" }}>
          <span style={{ width: "8px", height: "8px", background: "#22D3EE", borderRadius: "50%", display: "inline-block" }}></span>
          HYBRID PQC ENABLED
        </div>

        <div style={{ marginBottom: "2rem" }}>
          <h1 style={{ fontSize: "1.75rem", fontWeight: "600", color: "var(--color-text)", marginBottom: '0.5rem' }}>Compose Message</h1>
          <p style={{ color: "var(--color-muted)", fontSize: "0.9rem" }}>Secure End-to-End Encrypted Tunnel</p>
        </div>

        <form onSubmit={onSend} style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
            <div>
              <label style={{ fontSize: "0.8rem", color: "var(--color-muted)", display: 'block', marginBottom: '0.5rem' }}>From</label>
              <input className="input" value={fromEmail} readOnly style={{ background: "rgba(255,255,255,0.05)", opacity: 0.6, cursor: 'not-allowed' }} />
            </div>
            <div>
              <label style={{ fontSize: "0.8rem", color: "var(--color-muted)", display: 'block', marginBottom: '0.5rem' }}>To</label>
              <input className="input" value={toEmail} onChange={(e) => setToEmail(e.target.value)} placeholder="recipient@email.com" required />
            </div>
          </div>

          <div>
            <label style={{ fontSize: "0.8rem", color: "var(--color-muted)", display: 'block', marginBottom: '0.5rem' }}>Message Body</label>
            <textarea className="input" value={msg} onChange={(e) => setMsg(e.target.value)} placeholder="Write your quantum-safe message..." style={{ minHeight: "150px", width: '100%' }} required />
          </div>

          {/* Authentication Mode Selection */}
          <div style={{ padding: "1.25rem", background: "rgba(255, 255, 255, 0.02)", borderRadius: "0.75rem", border: "1px solid rgba(34, 211, 238, 0.1)" }}>
            <label style={{ fontSize: "0.875rem", color: "var(--color-muted)", display: "block", marginBottom: "0.75rem", fontWeight: "500" }}>Authentication Mode</label>
            <div style={{ display: "flex", gap: "1.5rem", flexWrap: "wrap" }}>
              <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer", fontSize: "0.9rem", color: "var(--color-text)" }}>
                <input type="radio" name="alg" checked={alg === "ed25519"} onChange={() => setAlg("ed25519")} style={{ accentColor: "#22D3EE" }} />
                <span>Ed25519 (Digital Signature)</span>
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer", fontSize: "0.9rem", color: "var(--color-text)" }}>
                <input type="radio" name="alg" checked={alg === "mac"} onChange={() => setAlg("mac")} style={{ accentColor: "#22D3EE" }} />
                <span>HMAC-SHA256 (Deniable Authenticity)</span>
              </label>
            </div>
            <div style={{ marginTop: "1rem", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <p style={{ fontSize: "0.75rem", color: "#22D3EE", fontWeight: "500" }}>Protocol: X25519 + ML-KEM-768</p>
              <p style={{ fontSize: "0.75rem", color: "var(--color-muted)" }}>Payload Overhead: ~1,120 B</p>
            </div>
          </div>

          {/* Real-time Crypto Audit Logs */}
          {cryptoLogs.length > 0 && (
            <div style={{ background: "#000", padding: "1rem", borderRadius: "8px", fontFamily: "monospace", fontSize: "0.75rem", color: "#22D3EE", border: "1px solid rgba(34, 211, 238, 0.2)" }}>
              <div style={{ marginBottom: "5px", color: "var(--color-muted)", textTransform: "uppercase", fontSize: "0.65rem" }}>Cryptographic Audit Trace:</div>
              {cryptoLogs.map((log, i) => (
                <div key={i}> {`> ${log}`}</div>
              ))}
            </div>
          )}

          <div style={{ display: "flex", gap: "1rem" }}>
            <button className="btn-primary" type="submit" disabled={sending} style={{ flex: 1, padding: "1rem", background: "linear-gradient(135deg, #22D3EE 0%, #3B82F6 100%)", border: "none", color: "#fff", fontWeight: "bold", borderRadius: "8px", cursor: sending ? 'not-allowed' : 'pointer' }}>
              {sending ? "Encrypting & Dispatched..." : "Encrypt & Send Message"}
            </button>
          </div>
        </form>

        {info && (
           <div style={{ marginTop: "1rem", padding: '0.75rem', borderRadius: '8px', background: info.includes("successfully") ? "rgba(34, 211, 238, 0.1)" : "rgba(239, 68, 68, 0.1)", color: info.includes("successfully") ? "#22D3EE" : "#fca5a5", fontSize: "0.85rem", textAlign: "center", border: '1px solid currentColor' }}>
             {info}
           </div>
        )}
      </div>
    </div>
  );
}
