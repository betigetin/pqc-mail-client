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
      setMsg("Quantum-safe keypair generated and stored in browser.");
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
    if (!k) { setMsg("No local keys found."); return; }

    setLoadingUpload(true);
    try {
      const pub = {
        x25519: k.x25519_pub,
        ed25519: k.ed25519_pub,
        pqc_kem: "ML-KEM-768", // Standard NIST naming
        kyber_pub: k.kyber_pub, // FIX: Sending the actual PQC public key
      };
      await api.uploadKeys(deviceId, pub, token);
      setMsg("Public bundle (X25519 + ML-KEM) uploaded successfully.");
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
      setTimeout(() => setCopied(null), 2000);
    } catch (e: any) {
      setMsg(`Copy failed: ${e?.message ?? String(e)}`);
    }
  }

  return (
    <div className="app-container" style={{ minHeight: '90vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '2rem' }}>
      <div style={{ maxWidth: '800px', width: '100%', background: 'var(--color-surface)', borderRadius: '1.25rem', padding: '2.5rem', border: '1px solid rgba(255, 255, 255, 0.05)', boxShadow: "0 20px 50px rgba(0,0,0,0.5)" }}>
        
        <div style={{ marginBottom: '2rem' }}>
          <h1 style={{ fontSize: '1.75rem', fontWeight: '600', color: 'var(--color-text)', marginBottom: '0.5rem' }}>Identity & Security Keys</h1>
          <p style={{ color: 'var(--color-muted)', fontSize: '0.9rem' }}>Manage your Classical (ECC) and Post-Quantum (PQC) keybundles.</p>
        </div>

        {/* Device ID */}
        <div style={{ marginBottom: '1.5rem' }}>
          <label style={{ fontSize: '0.8rem', color: 'var(--color-muted)', display: 'block', marginBottom: '0.5rem' }}>Active Device ID</label>
          <input className="input" value={deviceId} onChange={(e) => setDeviceId(e.target.value)} style={{ maxWidth: '300px' }} />
        </div>

        {/* Action Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '2rem' }}>
          <button className="btn-primary" onClick={gen} disabled={loadingGen} style={{ background: 'linear-gradient(135deg, #22D3EE 0%, #3B82F6 100%)', border: 'none', padding: '1rem' }}>
            {loadingGen ? "Computing Lattice..." : "🔑 Generate Hybrid Keys"}
          </button>
          <button className="btn-primary" onClick={upload} disabled={loadingUpload || !existing} style={{ background: 'transparent', border: '1px solid #22D3EE', color: '#22D3EE', padding: '1rem' }}>
             {loadingUpload ? "Publishing..." : "☁️ Publish Public Bundle"}
          </button>
        </div>

        {/* Key Display Area */}
        {existing ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            
            {/* Kyber / ML-KEM Section */}
            <KeyBox 
                title="ML-KEM-768 Public Key (Post-Quantum)" 
                val={existing.kyber_pub} 
                onCopy={() => copyToClipboard(existing.kyber_pub, "kyber")} 
                isCopied={copied === "kyber"}
                isPqc={true}
            />

            {/* X25519 Section */}
            <KeyBox 
                title="X25519 Public Key (Classical)" 
                val={existing.x25519_pub} 
                onCopy={() => copyToClipboard(existing.x25519_pub, "x25519")} 
                isCopied={copied === "x25519"}
            />

          </div>
        ) : (
          <div style={{ padding: '3rem', textAlign: 'center', border: '1px dashed rgba(255,255,255,0.1)', borderRadius: '12px' }}>
            <p style={{ color: 'var(--color-muted)' }}>No cryptographic identity found on this device.</p>
          </div>
        )}

        {msg && <div style={{ marginTop: '1.5rem', padding: '1rem', borderRadius: '8px', background: 'rgba(34, 211, 238, 0.1)', color: '#22D3EE', fontSize: '0.85rem', border: '1px solid #22D3EE' }}>{msg}</div>}
      </div>
    </div>
  );
}

// Sub-component for clean UI
function KeyBox({ title, val, onCopy, isCopied, isPqc }: any) {
  return (
    <div style={{ padding: '1rem', background: 'rgba(0,0,0,0.2)', borderRadius: '8px', border: isPqc ? '1px solid rgba(34, 211, 238, 0.3)' : '1px solid rgba(255,255,255,0.05)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
        <span style={{ fontSize: '0.7rem', fontWeight: 'bold', color: isPqc ? '#22D3EE' : 'var(--color-muted)', textTransform: 'uppercase' }}>{title}</span>
        <button onClick={onCopy} style={{ background: 'none', border: 'none', color: '#22D3EE', cursor: 'pointer', fontSize: '0.75rem' }}>{isCopied ? "DONE" : "COPY"}</button>
      </div>
      <div style={{ fontFamily: 'monospace', fontSize: '0.8rem', wordBreak: 'break-all', color: 'rgba(255,255,255,0.7)' }}>{val || "Not generated"}</div>
    </div>
  );
}
