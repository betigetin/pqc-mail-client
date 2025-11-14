import React, { useRef, useState } from "react";
import { useAuth } from "../state/auth";
import { api } from "../lib/api";
import { generateDeviceKeys, saveDeviceKeys, loadDeviceKeys } from "../lib/crypto";

export function Keys() {
  const { token } = useAuth();
  const [deviceId, setDeviceId] = useState("web-01");
  const [msg, setMsg] = useState<string>("");
  const [loadingGen, setLoadingGen] = useState(false);
  const [loadingUpload, setLoadingUpload] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const existing = loadDeviceKeys();

  async function gen() {
    setMsg("");
    setLoadingGen(true);
    try {
      const k = await generateDeviceKeys();
      saveDeviceKeys(k);
      setMsg("Keys generated and saved locally.");
    } catch (e: any) {
      setMsg(`Failed to generate: ${e?.message ?? String(e)}`);
    } finally {
      setLoadingGen(false);
    }
  }

  async function upload() {
    setMsg("");
    if (!token) { setMsg("Login required to upload keys."); return; }
    const k = loadDeviceKeys();
    if (!k) { setMsg("No local keys found; please generate or import first."); return; }

    setLoadingUpload(true);
    try {
      const pub = {
        x25519: k.x25519_pub,
        ed25519: k.ed25519_pub,
        pqc_kem: "Kyber768",
        pqc_pubkey: "",
      };
      await api.uploadKeys(deviceId, pub, token);
      setMsg("Device public keys uploaded to server successfully.");
    } catch (e: any) {
      setMsg(`Upload failed: ${e?.message ?? String(e)}`);
    } finally {
      setLoadingUpload(false);
    }
  }

  async function copyToClipboard(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(label);
      setMsg(`Copied ${label} to clipboard.`);
      setTimeout(() => setCopied(null), 2000);
    } catch (e: any) {
      setMsg(`Copy failed: ${e?.message ?? String(e)}`);
    }
  }

  function exportKeys() {
    const k = loadDeviceKeys();
    if (!k) { setMsg("No local keys to export."); return; }

    try {
      const payload = {
        x25519_pub: k.x25519_pub,
        x25519_priv: k.x25519_priv,
        ed25519_pub: k.ed25519_pub,
        ed25519_priv: k.ed25519_priv,
        created_at: new Date().toISOString(),
        note: "PQ Mail device keypair (keep private!)"
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vionyx-keys-${deviceId || "device"}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setMsg("Keys exported successfully — file downloaded.");
    } catch (e: any) {
      setMsg(`Export failed: ${e?.message ?? String(e)}`);
    }
  }

  function triggerImport() {
    setMsg("");
    fileInputRef.current?.click();
  }

  async function onFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    setMsg("");
    const f = e.target.files?.[0];
    if (!f) { setMsg("No file selected."); return; }
    try {
      const text = await f.text();
      let parsed: any;
      try {
        parsed = JSON.parse(text);
      } catch {
        setMsg("Invalid JSON file.");
        return;
      }
      if (!parsed.x25519_pub || !parsed.x25519_priv || !parsed.ed25519_pub || !parsed.ed25519_priv) {
        setMsg("Invalid key file: missing expected fields.");
        return;
      }
      saveDeviceKeys({
        x25519_pub: parsed.x25519_pub,
        x25519_priv: parsed.x25519_priv,
        ed25519_pub: parsed.ed25519_pub,
        ed25519_priv: parsed.ed25519_priv,
      });
      setMsg("Keys imported and saved locally.");
    } catch (err: any) {
      setMsg(`Import failed: ${err?.message ?? String(err)}`);
    } finally {
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    }
  }

  return (
    <div className="app-container" style={{ 
      minHeight: 'calc(100vh - 100px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '2rem'
    }}>
      <div style={{
        maxWidth: '800px',
        width: '100%',
        background: 'var(--color-surface)',
        borderRadius: '1.25rem',
        padding: '2.5rem',
        boxShadow: '0 20px 60px rgba(0, 0, 0, 0.4), 0 0 1px rgba(34, 211, 238, 0.1)',
        border: '1px solid rgba(255, 255, 255, 0.05)'
      }}>
        {/* Header */}
        <div style={{ marginBottom: '2rem' }}>
          <h1 style={{
            fontSize: '1.75rem',
            fontWeight: '600',
            marginBottom: '0.5rem',
            color: 'var(--color-text)'
          }}>Device Keys Management</h1>
          
          <p style={{
            fontSize: '0.95rem',
            color: 'var(--color-muted)',
            lineHeight: '1.5'
          }}>Generate cryptographic keys in your browser, export for backup, or import existing keypairs</p>
        </div>

        {/* Device ID Input */}
        <div style={{ marginBottom: '1.5rem' }}>
          <label style={{
            fontSize: '0.875rem',
            color: 'var(--color-muted)',
            display: 'block',
            marginBottom: '0.5rem',
            fontWeight: '500'
          }}>Device Identifier</label>
          <input
            className="input"
            value={deviceId}
            onChange={(e) => setDeviceId(e.target.value)}
            placeholder="e.g., web-01, mobile-alice, desktop-primary"
            style={{
              fontSize: '0.95rem',
              padding: '0.75rem 1rem',
              maxWidth: '400px'
            }}
          />
        </div>

        {/* Action Buttons */}
        <div style={{
          display: 'flex',
          gap: '0.75rem',
          flexWrap: 'wrap',
          marginBottom: '2rem',
          padding: '1.25rem',
          background: 'rgba(255, 255, 255, 0.02)',
          borderRadius: '0.75rem',
          border: '1px solid rgba(255, 255, 255, 0.05)'
        }}>
          <button 
            className="btn-primary" 
            onClick={gen} 
            disabled={loadingGen}
            style={{
              padding: '0.7rem 1.25rem',
              fontSize: '0.9rem',
              opacity: loadingGen ? 0.7 : 1
            }}
          >
            {loadingGen ? "Generating..." : "🔑 Generate New"}
          </button>

          <button
            className="btn-ghost"
            onClick={triggerImport}
            title="Import keys from a JSON file"
            style={{
              padding: '0.7rem 1.25rem',
              fontSize: '0.9rem'
            }}
          >
            📥 Import
          </button>

          <input
            ref={fileInputRef}
            type="file"
            accept="application/json"
            onChange={onFileChange}
            style={{ display: "none" }}
          />

          <button 
            className="btn-ghost" 
            onClick={exportKeys}
            disabled={!existing}
            style={{
              padding: '0.7rem 1.25rem',
              fontSize: '0.9rem',
              opacity: !existing ? 0.5 : 1,
              cursor: !existing ? 'not-allowed' : 'pointer'
            }}
          >
            📤 Export
          </button>

          <button 
            className="btn-primary" 
            onClick={upload} 
            disabled={loadingUpload || !existing}
            style={{
              padding: '0.7rem 1.25rem',
              fontSize: '0.9rem',
              opacity: (loadingUpload || !existing) ? 0.7 : 1,
              cursor: (loadingUpload || !existing) ? 'not-allowed' : 'pointer'
            }}
          >
            {loadingUpload ? "Uploading..." : "☁️ Upload to Server"}
          </button>
        </div>

        {/* Existing Keys Display */}
        {existing ? (
          <div style={{
            padding: '1.5rem',
            background: 'rgba(34, 211, 238, 0.03)',
            borderRadius: '0.75rem',
            border: '1px solid rgba(34, 211, 238, 0.15)'
          }}>
            <div style={{
              fontSize: '0.95rem',
              color: 'var(--color-text)',
              marginBottom: '1.25rem',
              fontWeight: '600'
            }}>📋 Stored Public Keys (Local Browser Storage)</div>

            {/* X25519 Public Key */}
            <div style={{ marginBottom: '1.5rem' }}>
              <div style={{
                fontSize: '0.8rem',
                color: 'var(--color-muted)',
                marginBottom: '0.5rem',
                fontWeight: '500',
                textTransform: 'uppercase',
                letterSpacing: '0.5px'
              }}>X25519 Public Key (Key Exchange)</div>
              <div style={{
                fontFamily: 'monospace',
                fontSize: '0.85rem',
                padding: '0.85rem',
                background: 'rgba(0, 0, 0, 0.3)',
                borderRadius: '0.5rem',
                wordBreak: 'break-all',
                color: '#22D3EE',
                border: '1px solid rgba(255, 255, 255, 0.05)'
              }}>
                {existing.x25519_pub}
              </div>
              <button 
                className="btn-ghost" 
                onClick={() => copyToClipboard(existing.x25519_pub, "x25519_pub")}
                style={{
                  marginTop: '0.5rem',
                  padding: '0.4rem 0.8rem',
                  fontSize: '0.85rem'
                }}
              >
                {copied === "x25519_pub" ? "✓ Copied!" : "📋 Copy"}
              </button>
            </div>

            {/* Ed25519 Public Key */}
            <div>
              <div style={{
                fontSize: '0.8rem',
                color: 'var(--color-muted)',
                marginBottom: '0.5rem',
                fontWeight: '500',
                textTransform: 'uppercase',
                letterSpacing: '0.5px'
              }}>Ed25519 Public Key (Digital Signature)</div>
              <div style={{
                fontFamily: 'monospace',
                fontSize: '0.85rem',
                padding: '0.85rem',
                background: 'rgba(0, 0, 0, 0.3)',
                borderRadius: '0.5rem',
                wordBreak: 'break-all',
                color: '#22D3EE',
                border: '1px solid rgba(255, 255, 255, 0.05)'
              }}>
                {existing.ed25519_pub}
              </div>
              <button 
                className="btn-ghost" 
                onClick={() => copyToClipboard(existing.ed25519_pub, "ed25519_pub")}
                style={{
                  marginTop: '0.5rem',
                  padding: '0.4rem 0.8rem',
                  fontSize: '0.85rem'
                }}
              >
                {copied === "ed25519_pub" ? "✓ Copied!" : "📋 Copy"}
              </button>
            </div>
          </div>
        ) : (
          <div style={{
            padding: '2rem',
            textAlign: 'center',
            background: 'rgba(255, 255, 255, 0.02)',
            borderRadius: '0.75rem',
            border: '1px dashed rgba(255, 255, 255, 0.1)'
          }}>
            <div style={{ fontSize: '2rem', marginBottom: '0.75rem' }}>🔐</div>
            <div style={{
              fontSize: '0.95rem',
              color: 'var(--color-muted)',
              lineHeight: '1.6'
            }}>
              No device keys found in local storage.<br/>
              Generate new keys or import an existing keypair to get started.
            </div>
          </div>
        )}

        {/* Status Message */}
        {msg && (
          <div style={{
            marginTop: '1.5rem',
            padding: '0.85rem 1.1rem',
            background: msg.toLowerCase().includes("failed") || msg.toLowerCase().includes("invalid")
              ? 'rgba(239, 68, 68, 0.1)' 
              : 'rgba(34, 211, 238, 0.1)',
            border: msg.toLowerCase().includes("failed") || msg.toLowerCase().includes("invalid")
              ? '1px solid rgba(239, 68, 68, 0.3)'
              : '1px solid rgba(34, 211, 238, 0.3)',
            borderRadius: '0.5rem',
            color: msg.toLowerCase().includes("failed") || msg.toLowerCase().includes("invalid") 
              ? '#fca5a5' 
              : '#22D3EE',
            fontSize: '0.9rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}>
            <span>{msg.toLowerCase().includes("failed") || msg.toLowerCase().includes("invalid") ? "⚠️" : "✓"}</span>
            <span>{msg}</span>
          </div>
        )}

        {/* Footer Info */}
        <div style={{
          marginTop: '1.5rem',
          paddingTop: '1.5rem',
          borderTop: '1px solid rgba(255, 255, 255, 0.05)',
          fontSize: '0.8rem',
          color: 'var(--color-muted)',
          lineHeight: '1.6'
        }}>
          <strong>⚠️ Security Note:</strong> Private keys are stored only in your browser's local storage. 
          Export and backup your keys securely. Never share your private keys with anyone.
        </div>
      </div>
    </div>
  );
}
