// front/src/pages/Inbox.tsx
import React, { useEffect, useState } from "react";
import { useAuth } from "../state/auth";
import { api } from "../lib/api";
import { b64d, utf8d } from "../lib/b64";
import {
  loadDeviceKeys,
  x25519Shared,
  deriveAeadKey,
  deriveMacKey,
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

  // ---------- REPLACED tryDecrypt (verbose debugging) ----------
  async function tryDecrypt(m: any): Promise<string | null> {
    // Very verbose debugging wrapper to find where "bad n size" originates
    try {
      console.log(">>> tryDecrypt start for msg", m.id);
      const keys = loadDeviceKeys();
      if (!keys) {
        console.log("  no device keys loaded");
        return "(no device keys loaded)";
      }

      const p = m.payload;
      const sigAlg = p.sig_alg ?? "ed25519";
      console.log("  sigAlg:", sigAlg);

      if (!["ed25519", "mac", "hybrid", "dr"].includes(sigAlg)) {
        console.log("  unsupported alg:", sigAlg);
        return `(unsupported alg: ${sigAlg})`;
      }
      if (sigAlg === "dr") return "(Double Ratchet message: not supported in this demo.)";
      if (sigAlg === "hybrid") return "(Hybrid PQC message: not supported in this demo.)";

      const eph = p.handshake?.ephemeral_x25519_pub;
      if (!eph) {
        console.log("  missing ephemeral");
        return "(missing ephemeral)";
      }

      // DEBUG: payload raw
      console.log("  payload snapshot:", {
        id: m.id,
        from: m.from,
        handshake_ephemeral_b64: p.handshake?.ephemeral_x25519_pub,
        nonce_b64: p.nonce,
        ciphertext_b64_len: p.ciphertext ? p.ciphertext.length : null,
        aad_b64_len: p.aad ? p.aad.length : null,
      });

      // Compute shared secret & derived keys
      let ss: Uint8Array;
      try {
        ss = x25519Shared(keys.x25519_priv, eph);
        console.log("  shared secret length:", ss?.length);
        console.log(
          "  shared secret (hex, first 16 bytes):",
          Array.from(ss.slice(0, 16))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("")
        );
      } catch (e) {
        console.error("  FAILED computing shared secret:", e);
        return `⛔ Failed computing shared secret: ${String(e?.message ?? e)}`;
      }

      let key: Uint8Array;
      try {
        key = deriveAeadKey(ss);
        console.log("  derived aead key length:", key?.length);
        console.log(
          "  derived aead key (hex, first 16 bytes):",
          Array.from(key.slice(0, 16))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("")
        );
      } catch (e) {
        console.error("  FAILED deriveAeadKey:", e);
        return `⛔ Failed deriving AEAD key: ${String(e?.message ?? e)}`;
      }

      // Decode ciphertext safely
      let ct: Uint8Array;
      try {
        ct = b64d(p.ciphertext);
        console.log("  ciphertext decoded length:", ct.length);
      } catch (e) {
        console.error("  FAILED decoding ciphertext (b64d):", e);
        return `⛔ Failed to decode ciphertext: ${String(e?.message ?? e)}`;
      }

      // Decode nonce safely
      let nonce: Uint8Array;
      try {
        // Debug raw string before decode
        console.log("  nonce (raw b64):", p.nonce, "type:", typeof p.nonce, "len:", p.nonce?.length);
        nonce = b64d(p.nonce);
        console.log("  nonce decoded length:", nonce.length, "bytes");
        console.log("  nonce bytes:", Array.from(nonce));
      } catch (e) {
        console.error("  FAILED decoding nonce (b64d):", e);
        return `⛔ Failed to decode nonce: ${String(e?.message ?? e)}`;
      }

      // AAD
      let aad: Uint8Array | undefined = undefined;
      if (p.aad) {
        try {
          aad = b64d(p.aad);
          console.log("  aad decoded length:", aad.length);
        } catch (e) {
          console.error("  FAILED decoding aad (b64d):", e);
          return `⛔ Failed to decode aad: ${String(e?.message ?? e)}`;
        }
      }

      // Sanity checks
      if (!nonce || nonce.length !== 12) {
        console.error("  nonce length check failed:", nonce ? nonce.length : nonce);
        return `⛔ Invalid nonce size: expected 12 bytes, got ${nonce ? nonce.length : 0}`;
      }
      if (!key || key.length !== 32) {
        console.error("  aead key length check failed:", key ? key.length : key);
        return `⛔ Invalid AEAD key size: expected 32 bytes, got ${key ? key.length : 0}`;
      }

      // Now attempt verify / decrypt depending on alg
      if (sigAlg === "ed25519") {
        // fetch sender pubkey (safe)
        let edpk: string | undefined;
        try {
          const senderKeys = await api.fetchKeysByHash(m.from);
          edpk = senderKeys?.devices?.[0]?.device_pubkeys?.ed25519;
          console.log("  sender ed25519 pubkey:", edpk ? edpk.slice(0, 8) + "..." : "(none)");
        } catch (e) {
          console.warn("  failed fetching sender keys:", e);
        }

        const signedBytes = new Uint8Array([
          ...b64d(eph),
          ...nonce,
          ...ct,
          ...(aad || new Uint8Array()),
        ]);
        const sig = p.signature ? b64d(p.signature) : null;

        // verify signature
        if (!edpk || !sig) {
          console.warn("  missing ed pk or sig (edpk:", !!edpk, "sig:", !!sig, ")");
          // fallthrough to mac or failure below
        } else {
          const ok = edVerify(edpk, signedBytes, sig);
          console.log("  ed25519 verify result:", ok);
          if (ok) {
            const pt = aeadDecrypt(key, nonce, ct, aad);
            return utf8d(pt);
          } else {
            console.warn("  ed25519 signature invalid for msg", m.id);
            // fall through to try mac below
          }
        }
      }

      if (sigAlg === "mac" || sigAlg === "ed25519") {
        // attempt MAC verification path (works if sender put HMAC in signature)
        try {
          // mac key derivation
          const macKey = deriveMacKey(ss);
          const signedBytes = new Uint8Array([
            ...b64d(eph),
            ...nonce,
            ...ct,
            ...(aad || new Uint8Array()),
          ]);
          const macComputed = await hmacSha256(macKey, signedBytes);
          const macRemote = p.signature ? b64d(p.signature) : null;
          console.log("  macComputed length:", macComputed.length, "macRemote length:", macRemote ? macRemote.length : null);

          if (macRemote) {
            // constant-time compare
            if (macRemote.length === macComputed.length) {
              let equal = true;
              for (let i = 0; i < macComputed.length; i++) if (macComputed[i] !== macRemote[i]) { equal = false; break; }
              console.log("  mac verification equal:", equal);
              if (equal) {
                const pt = aeadDecrypt(key, nonce, ct, aad);
                return utf8d(pt);
              } else {
                console.warn("  MAC mismatch");
                // continue to final error
              }
            } else {
              console.warn("  MAC length mismatch");
            }
          } else {
            console.warn("  no mac present in payload.signature");
          }
        } catch (e) {
          console.error("  MAC verification or decrypt threw:", e);
          return `⛔ MAC verification / decrypt error: ${String(e?.message ?? e)}`;
        }
      }

      // If we get here, decryption / verification failed
      return "⛔ Decryption failed (signature/MAC verification failed or AEAD failed).";
    } catch (e: any) {
      // top-level catch — log full stack for inspection
      console.error("!!! tryDecrypt top-level exception for msg", m.id, e);
      if (e && e.stack) console.error(e.stack);
      return `⛔ ${String(e?.message ?? e)}`;
    }
  }
  // ---------- end tryDecrypt replacement ----------

  return (
    <div
      className="app-container"
      style={{
        minHeight: "calc(100vh - 100px)",
        padding: "2rem",
      }}
    >
      <div
        style={{
          maxWidth: "900px",
          margin: "0 auto",
          background: "var(--color-surface)",
          borderRadius: "1.25rem",
          padding: "2.5rem",
          boxShadow: "0 20px 60px rgba(0, 0, 0, 0.4), 0 0 1px rgba(34, 211, 238, 0.1)",
          border: "1px solid rgba(255, 255, 255, 0.05)",
        }}
      >
        {/* Header */}
        <div style={{ marginBottom: "2rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.5rem" }}>
            <span style={{ fontSize: "1.5rem" }}></span>
            <h1
              style={{
                fontSize: "1.75rem",
                fontWeight: "600",
                color: "var(--color-text)",
              }}
            >
              Inbox
            </h1>
            {items.length > 0 && (
              <span
                style={{
                  padding: "0.25rem 0.75rem",
                  background: "rgba(34, 211, 238, 0.15)",
                  color: "#22D3EE",
                  borderRadius: "1rem",
                  fontSize: "0.85rem",
                  fontWeight: "600",
                }}
              >
                {items.length}
              </span>
            )}
          </div>

          <p
            style={{
              fontSize: "0.95rem",
              color: "var(--color-muted)",
              lineHeight: "1.5",
            }}
          >
            End-to-end encrypted messages. Click to decrypt and view content.
          </p>
        </div>

        {/* Messages List */}
        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          {items.length === 0 && (
            <div
              style={{
                padding: "3rem 2rem",
                textAlign: "center",
                background: "rgba(255, 255, 255, 0.02)",
                borderRadius: "0.75rem",
                border: "1px dashed rgba(255, 255, 255, 0.1)",
              }}
            >
              <div style={{ fontSize: "3rem", marginBottom: "1rem" }}>📭</div>
              <div
                style={{
                  fontSize: "1.1rem",
                  color: "var(--color-text)",
                  marginBottom: "0.5rem",
                  fontWeight: "500",
                }}
              >
                No messages yet
              </div>
              <div
                style={{
                  fontSize: "0.9rem",
                  color: "var(--color-muted)",
                  lineHeight: "1.6",
                }}
              >
                Your encrypted messages will appear here once you receive them.
              </div>
            </div>
          )}
          {items.map((m) => (
            <MessageItem key={m.id} m={m} tryDecrypt={tryDecrypt} />
          ))}
        </div>

        {/* Debug Log */}
        {log && (
          <div
            style={{
              marginTop: "2rem",
              paddingTop: "1.5rem",
              borderTop: "1px solid rgba(255, 255, 255, 0.05)",
            }}
          >
            <div
              style={{
                fontSize: "0.85rem",
                color: "var(--color-muted)",
                marginBottom: "0.5rem",
                fontWeight: "600",
              }}
            >
              🔍 Debug Information:
            </div>
            <pre
              style={{
                fontSize: "0.75rem",
                padding: "0.85rem",
                background: "rgba(0, 0, 0, 0.3)",
                borderRadius: "0.5rem",
                color: "#22D3EE",
                overflowX: "auto",
                fontFamily: "monospace",
                border: "1px solid rgba(255, 255, 255, 0.05)",
              }}
            >
              {log}
            </pre>
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

  // Determine if decryption failed
  const isFailed = plain?.startsWith("⛔") || plain?.startsWith("(");

  // Get algorithm display info
  const algInfo =
    {
      ed25519: { label: "Ed25519", color: "#22D3EE", bg: "rgba(34, 211, 238, 0.1)" },
      mac: { label: "MAC", color: "#3B82F6", bg: "rgba(59, 130, 246, 0.1)" },
      hybrid: { label: "Hybrid", color: "#8B5CF6", bg: "rgba(139, 92, 246, 0.1)" },
      dr: { label: "DR", color: "#10B981", bg: "rgba(16, 185, 129, 0.1)" },
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
        // Only toggle if clicking on the card itself, not on buttons
        if ((e.target as HTMLElement).tagName !== "BUTTON") {
          onToggle();
        }
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-start", gap: "1rem" }}>
        {/* Message ID Badge */}
       {/* Message ID Badge */}
<div style={{
  minWidth: '40px',
  height: '40px',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  background: 'rgba(34, 211, 238, 0.1)',
  border: '1px solid rgba(34, 211, 238, 0.2)',
  borderRadius: '0.5rem',
  fontSize: '0.85rem',
  fontWeight: '600',
  color: '#22D3EE'
}}>
  #
</div>
 

        {/* Message Content */}
        <div style={{ flex: 1, minWidth: 0 }}>
          {/* Header Row */}
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.5rem", flexWrap: "wrap" }}>
            <div
              style={{
                fontSize: "1rem",
                fontWeight: "600",
                color: "var(--color-text)",
              }}
            >
              {m.payload?.subject ?? `Message #`}
            </div>

            {/* Algorithm Badge */}
            <div
              style={{
                padding: "0.25rem 0.65rem",
                background: algInfo.bg,
                color: algInfo.color,
                borderRadius: "0.35rem",
                fontSize: "0.75rem",
                fontWeight: "600",
                textTransform: "uppercase",
                letterSpacing: "0.5px",
              }}
            >
              {algInfo.label}
            </div>
          </div>

          {/* Metadata Row */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "1rem",
              fontSize: "0.85rem",
              color: "var(--color-muted)",
              marginBottom: "0.75rem",
            }}
          >
            <span>
              📤 From: <span style={{ fontFamily: "monospace", color: "#22D3EE" }}>{fromShort}</span>
            </span>
            <span>🕒 {new Date(m.created_at || Date.now()).toLocaleString()}</span>
          </div>

          {/* Action Button */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              onToggle();
            }}
            className="btn-ghost"
            style={{
              padding: "0.5rem 1rem",
              fontSize: "0.85rem",
              fontWeight: "500",
            }}
            aria-expanded={open}
          >
            {loading ? "🔓 Decrypting..." : open ? "🔒 Hide Message" : "🔓 Decrypt & View"}
          </button>

          {/* Decrypted Content */}
          {open && (
            <div
              style={{
                marginTop: "1rem",
                paddingTop: "1rem",
                borderTop: "1px solid rgba(255, 255, 255, 0.05)",
              }}
            >
              <div
                style={{
                  fontSize: "0.8rem",
                  color: "var(--color-muted)",
                  marginBottom: "0.5rem",
                  fontWeight: "600",
                  textTransform: "uppercase",
                  letterSpacing: "0.5px",
                }}
              >
                {isFailed ? "⚠️ Decryption Status" : "✓ Decrypted Message"}
              </div>
              <div
                style={{
                  fontFamily: plain?.startsWith("⛔") || plain?.startsWith("(") ? "monospace" : "inherit",
                  fontSize: "0.95rem",
                  padding: "1rem",
                  background: isFailed ? "rgba(239, 68, 68, 0.1)" : "rgba(0, 0, 0, 0.3)",
                  borderRadius: "0.5rem",
                  wordBreak: "break-word",
                  color: isFailed ? "#fca5a5" : "var(--color-text)",
                  border: isFailed ? "1px solid rgba(239, 68, 68, 0.3)" : "1px solid rgba(255, 255, 255, 0.05)",
                  lineHeight: "1.6",
                }}
              >
                {plain ?? "(could not decrypt)"}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

