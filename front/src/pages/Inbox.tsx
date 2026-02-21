import React, { useEffect, useState } from "react";
import { useAuth } from "../state/auth";
import { api } from "../lib/api";
import { b64d, utf8d } from "../lib/b64";
// FIX: Correct Import from local Kyber file
import { Kyber768 } from "../lib/kyber_lib";
import {
  loadDeviceKeys,
  x25519Shared,
  deriveAeadKey,
  deriveMacKey,
  deriveHybridSecret, // Make sure this is imported
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
        setItems((res.messages || []).sort((a: any, b: any) => b.id - a.id)); // newest first
      } catch (e: any) {
        setLog(String(e?.message ?? e));
      }
    })();
  }, [token]);

  // ---------- HYBRID DECRYPTION LOGIC ----------
  async function tryDecrypt(m: any): Promise<string | null> {
    try {
      console.log(">>> tryDecrypt start for msg", m.id);
      const keys = loadDeviceKeys();
      if (!keys) {
        return "(no device keys loaded)";
      }

      const p = m.payload;
      const sigAlg = p.sig_alg ?? "ed25519";
      
      // Allow 'hybrid' or standard algs
      if (!["ed25519", "mac", "hybrid"].includes(sigAlg)) {
        return `(unsupported alg: ${sigAlg})`;
      }

      const eph = p.handshake?.ephemeral_x25519_pub;
      if (!eph) {
        return "(missing ephemeral key)";
      }

      // ---------------------------------------------------------
      // 1. HYBRID KEY DERIVATION START
      // ---------------------------------------------------------
      let key: Uint8Array;

      try {
        // A. Classical Shared Secret (X25519)
        const ss_classic = x25519Shared(keys.x25519_priv, eph);
        console.log("  ss_classic length:", ss_classic?.length);

        // B. Post-Quantum Shared Secret (Kyber-768)
        let ss_pq: Uint8Array;

        // Check for Kyber ciphertext in the handshake
        if (p.handshake?.kyber_ciphertext) {
          console.log("  Found Kyber ciphertext. Performing PQC Decapsulation...");

          if (!keys.kyber_priv) {
            throw new Error("Device keys missing Kyber private key. Re-generate keys.");
          }

          const kyber_ct = b64d(p.handshake.kyber_ciphertext);
          const kyber_sk = b64d(keys.kyber_priv);

          // Instantiate Local Kyber Lib
          const receiver = new Kyber768();
          // Decapsulate
          ss_pq = await receiver.decap(kyber_ct, kyber_sk);
          
          console.log("  ss_pq derived, length:", ss_pq.length);
        } else {
          console.warn("  ⚠️ No Kyber ciphertext. Falling back to Classical Security only.");
          ss_pq = new Uint8Array(0); 
        }

        // C. Combine (Mix X25519 + Kyber)
        const hybridRoot = deriveHybridSecret(ss_classic, ss_pq);

        // D. Final AEAD Key
        key = deriveAeadKey(hybridRoot);
        console.log("  Hybrid AEAD key derived. Length:", key?.length);

      } catch (e: any) {
        console.error("  FAILED computing hybrid keys:", e);
        return `⛔ Failed computing hybrid keys: ${e.message}`;
      }
      // ---------------------------------------------------------
      // HYBRID KEY DERIVATION END
      // ---------------------------------------------------------

      // --- The rest is standard decryption (Nonce decoding, verification, etc) ---

      let nonce: Uint8Array;
      let ct: Uint8Array;
      let aad: Uint8Array | undefined;

      try {
        nonce = b64d(p.nonce);
        ct = b64d(p.ciphertext);
        if (p.aad) aad = b64d(p.aad);
      } catch (e) {
        return "⛔ Failed to decode base64 fields";
      }

      // Verify Signatures or MAC
      if (sigAlg === "ed25519") {
        let edpk: string | undefined;
        try {
           const senderKeys = await api.fetchKeysByHash(m.from);
           const device = senderKeys?.devices?.find((d:any) => d.device_id === p.from_device_id) 
                          || senderKeys?.devices?.[0];
           edpk = device?.device_pubkeys?.ed25519;
        } catch (e) { console.warn("Failed fetching sender keys", e); }

        if (edpk && p.signature) {
           const signedBytes = new Uint8Array([...b64d(eph), ...nonce, ...ct, ...(aad || [])]);
           const ok = edVerify(edpk, signedBytes, b64d(p.signature));
           if (!ok) console.warn("Ed25519 signature invalid");
        }
      }

      // Decrypt
      const pt = aeadDecrypt(key, nonce, ct, aad);
      return utf8d(pt);

    } catch (e: any) {
      console.error("Decryption exception:", e);
      return `⛔ ${e.message}`;
    }
  }

  return (
    <div className="app-container" style={{ minHeight: "calc(100vh - 100px)", padding: "2rem" }}>
      <div style={{ maxWidth: "900px", margin: "0 auto", background: "var(--color-surface)", borderRadius: "1.25rem", padding: "2.5rem", boxShadow: "0 20px 60px rgba(0, 0, 0, 0.4), 0 0 1px rgba(34, 211, 238, 0.1)", border: "1px solid rgba(255, 255, 255, 0.05)" }}>
        {/* Header */}
        <div style={{ marginBottom: "2rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.5rem" }}>
            <h1 style={{ fontSize: "1.75rem", fontWeight: "600", color: "var(--color-text)" }}>Inbox</h1>
            {items.length > 0 && (
              <span style={{ padding: "0.25rem 0.75rem", background: "rgba(34, 211, 238, 0.15)", color: "#22D3EE", borderRadius: "1rem", fontSize: "0.85rem", fontWeight: "600" }}>
                {items.length}
              </span>
            )}
          </div>
          <p style={{ fontSize: "0.95rem", color: "var(--color-muted)", lineHeight: "1.5" }}>
            End-to-end encrypted messages. Click to decrypt and view content.
          </p>
        </div>

        {/* Messages List */}
        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          {items.length === 0 && (
            <div style={{ padding: "3rem 2rem", textAlign: "center", background: "rgba(255, 255, 255, 0.02)", borderRadius: "0.75rem", border: "1px dashed rgba(255, 255, 255, 0.1)" }}>
              <div style={{ fontSize: "3rem", marginBottom: "1rem" }}>📭</div>
              <div style={{ fontSize: "1.1rem", color: "var(--color-text)", marginBottom: "0.5rem", fontWeight: "500" }}>No messages yet</div>
              <div style={{ fontSize: "0.9rem", color: "var(--color-muted)", lineHeight: "1.6" }}>Your encrypted messages will appear here once you receive them.</div>
            </div>
          )}
          {items.map((m) => (
            <MessageItem key={m.id} m={m} tryDecrypt={tryDecrypt} />
          ))}
        </div>

        {/* Debug Log */}
        {log && (
          <div style={{ marginTop: "2rem", paddingTop: "1.5rem", borderTop: "1px solid rgba(255, 255, 255, 0.05)" }}>
            <div style={{ fontSize: "0.85rem", color: "var(--color-muted)", marginBottom: "0.5rem", fontWeight: "600" }}>🔍 Debug Information:</div>
            <pre style={{ fontSize: "0.75rem", padding: "0.85rem", background: "rgba(0, 0, 0, 0.3)", borderRadius: "0.5rem", color: "#22D3EE", overflowX: "auto", fontFamily: "monospace", border: "1px solid rgba(255, 255, 255, 0.05)" }}>{log}</pre>
          </div>
        )}
      </div>
    </div>
  );
}

function MessageItem({ m, tryDecrypt }: { m: any; tryDecrypt: (m: any) => Promise<string | null> }) {
  const [open, setOpen] = useState(false);
  const [plain, setPlain] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onToggle() {
    if (!open && plain === null) {
      setLoading(true);
      const pt = await tryDecrypt(m);
      setPlain(pt);
      setLoading(false);
      setOpen(true);
      return;
    }
    setOpen(!open);
  }

  const alg = m.payload?.sig_alg ?? "unknown";
  const fromShort = (m.from || "").slice(0, 10) + (m.from?.length > 10 ? "…" : "");
  const isFailed = plain?.startsWith("⛔") || plain?.startsWith("(");

  const algInfo = {
    ed25519: { label: "Ed25519", color: "#22D3EE", bg: "rgba(34, 211, 238, 0.1)" },
    mac: { label: "MAC", color: "#3B82F6", bg: "rgba(59, 130, 246, 0.1)" },
    hybrid: { label: "Hybrid", color: "#8B5CF6", bg: "rgba(139, 92, 246, 0.1)" },
  }[alg] || { label: alg, color: "#94A3B8", bg: "rgba(148, 163, 184, 0.1)" };

  return (
    <div
      style={{
        background: open ? "rgba(34, 211, 238, 0.03)" : "rgba(255, 255, 255, 0.02)",
        border: open ? "1px solid rgba(34, 211, 238, 0.2)" : "1px solid rgba(255, 255, 255, 0.05)",
        borderRadius: "0.75rem",
        padding: "1.25rem",
        transition: "all 200ms ease",
        cursor: "pointer",
      }}
      onClick={(e) => {
        if ((e.target as HTMLElement).tagName !== "BUTTON") onToggle();
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-start", gap: "1rem" }}>
        <div style={{ minWidth: "40px", height: "40px", display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(34, 211, 238, 0.1)", border: "1px solid rgba(34, 211, 238, 0.2)", borderRadius: "0.5rem", fontSize: "0.85rem", fontWeight: "600", color: "#22D3EE" }}>#</div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.5rem", flexWrap: "wrap" }}>
            <div style={{ fontSize: "1rem", fontWeight: "600", color: "var(--color-text)" }}>{m.payload?.subject ?? `Message`}</div>
            <div style={{ padding: "0.25rem 0.65rem", background: algInfo.bg, color: algInfo.color, borderRadius: "0.35rem", fontSize: "0.75rem", fontWeight: "600", textTransform: "uppercase", letterSpacing: "0.5px" }}>{algInfo.label}</div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "1rem", fontSize: "0.85rem", color: "var(--color-muted)", marginBottom: "0.75rem" }}>
            <span>📤 From: <span style={{ fontFamily: "monospace", color: "#22D3EE" }}>{fromShort}</span></span>
            <span>🕒 {new Date(m.created_at || Date.now()).toLocaleString()}</span>
          </div>
          <button onClick={(e) => { e.stopPropagation(); onToggle(); }} className="btn-ghost" style={{ padding: "0.5rem 1rem", fontSize: "0.85rem", fontWeight: "500" }}>
            {loading ? "🔓 Decrypting..." : open ? "🔒 Hide Message" : "🔓 Decrypt & View"}
          </button>
          {open && (
            <div style={{ marginTop: "1rem", paddingTop: "1rem", borderTop: "1px solid rgba(255, 255, 255, 0.05)" }}>
              <div style={{ fontSize: "0.8rem", color: "var(--color-muted)", marginBottom: "0.5rem", fontWeight: "600", textTransform: "uppercase", letterSpacing: "0.5px" }}>{isFailed ? "⚠️ Decryption Status" : "✓ Decrypted Message"}</div>
              <div style={{ fontFamily: isFailed ? "monospace" : "inherit", fontSize: "0.95rem", padding: "1rem", background: isFailed ? "rgba(239, 68, 68, 0.1)" : "rgba(0, 0, 0, 0.3)", borderRadius: "0.5rem", wordBreak: "break-word", color: isFailed ? "#fca5a5" : "var(--color-text)", border: isFailed ? "1px solid rgba(239, 68, 68, 0.3)" : "1px solid rgba(255, 255, 255, 0.05)", lineHeight: "1.6" }}>{plain ?? "(could not decrypt)"}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
