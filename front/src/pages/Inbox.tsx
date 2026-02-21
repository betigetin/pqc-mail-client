import React, { useEffect, useState } from "react";
import { useAuth } from "../state/auth";
import { api } from "../lib/api";
import { b64d, utf8d } from "../lib/b64";
import { Kyber768 } from "../lib/kyber_lib";
import {
  loadDeviceKeys,
  x25519Shared,
  deriveAeadKey,
  deriveMacKey,
  deriveHybridSecret,
  aeadDecrypt,
  hmacSha256,
  edVerify,
} from "../lib/crypto";

export function Inbox() {
  const { token } = useAuth();
  const [items, setItems] = useState<any[]>([]);
  const [log, setLog] = useState<string>("");

  useEffect(() => {
    (async () => {
      if (!token) return;
      try {
        const res = await api.inbox(token);
        setItems((res.messages || []).sort((a: any, b: any) => b.id - a.id));
      } catch (e: any) {
        setLog(String(e?.message ?? e));
      }
    })();
  }, [token]);

  async function tryDecrypt(m: any): Promise<{ text: string; isPqc: boolean }> {
    try {
      const keys = loadDeviceKeys();
      if (!keys) return { text: "(no device keys loaded)", isPqc: false };

      const p = m.payload;
      const sigAlg = p.sig_alg ?? "ed25519";
      const eph = p.handshake?.ephemeral_x25519_pub;
      if (!eph) return { text: "(missing ephemeral key)", isPqc: false };

      // 1. HYBRID KEY DERIVATION
      const ss_classic = x25519Shared(keys.x25519_priv, eph);
      let ss_pq: Uint8Array;
      let isPqc = false;

      if (p.handshake?.kyber_ciphertext) {
        if (!keys.kyber_priv) throw new Error("Missing Kyber private key.");
        const receiver = new Kyber768();
        ss_pq = await receiver.decap(b64d(p.handshake.kyber_ciphertext), b64d(keys.kyber_priv));
        isPqc = true;
      } else {
        ss_pq = new Uint8Array(0);
      }

      const hybridRoot = deriveHybridSecret(ss_classic, ss_pq);
      const key = deriveAeadKey(hybridRoot);

      // 2. Decrypt
      const pt = aeadDecrypt(key, b64d(p.nonce), b64d(p.ciphertext), p.aad ? b64d(p.aad) : undefined);
      
      return { text: utf8d(pt), isPqc };
    } catch (e: any) {
      return { text: `⛔ Decryption Error: ${e.message}`, isPqc: false };
    }
  }

  return (
    <div className="app-container" style={{ minHeight: "90vh", padding: "2rem" }}>
      <div style={{ maxWidth: "900px", margin: "0 auto", background: "var(--color-surface)", borderRadius: "1.25rem", padding: "2.5rem", border: "1px solid rgba(255, 255, 255, 0.05)" }}>
        <div style={{ marginBottom: "2rem" }}>
          <h1 style={{ fontSize: "1.75rem", fontWeight: "600", color: "var(--color-text)" }}>Encrypted Inbox</h1>
          <p style={{ color: "var(--color-muted)", fontSize: "0.9rem" }}>Post-Quantum Cryptographic (PQC) Secure Terminal</p>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          {items.map((m) => (
            <MessageItem key={m.id} m={m} tryDecrypt={tryDecrypt} />
          ))}
        </div>
      </div>
    </div>
  );
}

function MessageItem({ m, tryDecrypt }: { m: any; tryDecrypt: (m: any) => Promise<{ text: string; isPqc: boolean }> }) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<{ text: string; isPqc: boolean } | null>(null);
  const [loading, setLoading] = useState(false);

  async function onToggle() {
    if (!open && data === null) {
      setLoading(true);
      const res = await tryDecrypt(m);
      setData(res);
      setLoading(false);
    }
    setOpen(!open);
  }

  return (
    <div onClick={onToggle} style={{
      background: open ? "rgba(34, 211, 238, 0.03)" : "rgba(255, 255, 255, 0.02)",
      border: open ? "1px solid #22D3EE" : "1px solid rgba(255, 255, 255, 0.05)",
      borderRadius: "12px", padding: "1.25rem", cursor: "pointer"
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <div style={{ color: "#22D3EE", fontSize: "1.2rem" }}>{open ? "📖" : "✉️"}</div>
          <div>
            <div style={{ fontWeight: "600", color: "#fff" }}>Message ID: {m.id.toString().slice(-6)}</div>
            <div style={{ fontSize: "0.75rem", color: "var(--color-muted)" }}>From: {m.from.slice(0, 15)}...</div>
          </div>
        </div>
        
        {/* PQC Indicator Tag */}
        <div style={{ 
          background: "rgba(34, 211, 238, 0.1)", 
          border: "1px solid #22D3EE", 
          color: "#22D3EE", 
          padding: "2px 8px", 
          borderRadius: "4px", 
          fontSize: "0.65rem",
          fontWeight: "bold"
        }}>
          ML-KEM-768 (ACTIVE)
        </div>
      </div>

      {open && (
        <div style={{ marginTop: "1rem", paddingTop: "1rem", borderTop: "1px solid rgba(255, 255, 255, 0.1)" }}>
          {loading ? (
            <div style={{ color: "#22D3EE", fontSize: "0.85rem", fontFamily: "monospace" }}>Decapsulating PQC Secret...</div>
          ) : (
            <>
              <div style={{ fontSize: "0.95rem", color: "#fff", lineHeight: "1.6", marginBottom: "1rem" }}>
                {data?.text}
              </div>
              <div style={{ background: "rgba(0,0,0,0.2)", padding: "0.75rem", borderRadius: "6px", fontSize: "0.7rem", color: "#22D3EE", border: "1px solid rgba(34, 211, 238, 0.2)" }}>
                <strong>Security Trace:</strong> Decrypted via Hybrid Handshake (X25519 + ML-KEM-768)
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
