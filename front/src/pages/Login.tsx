import React, { useState } from "react";
import { api } from "../lib/api";
import { useAuth } from "../state/auth";
import { useNavigate, useLocation, Link } from "react-router-dom";

export function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const { setToken } = useAuth();
  const nav = useNavigate();
  const loc = useLocation() as any;
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setLoading(true);
    try {
      const { token } = await api.login(email, password);
      setToken(token);
      nav(loc.state?.from?.pathname || "/inbox", { replace: true });
    } catch (e: any) {
      setErr(e?.message || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app-container" style={{ 
      minHeight: '100vh', display: 'flex', alignItems: 'center', 
      justifyContent: 'center', padding: '2rem', background: '#0a0a0a' 
    }}>
      <div style={{
        maxWidth: '440px', width: '100%', background: 'var(--color-surface)',
        borderRadius: '1.25rem', padding: '2.5rem',
        boxShadow: '0 20px 60px rgba(0, 0, 0, 0.4)',
        border: '1px solid rgba(255, 255, 255, 0.05)'
      }}>
        {/* Latticemail Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '2rem', justifyContent: 'center' }}>
          <div style={{ 
            background: 'rgba(34, 211, 238, 0.1)', border: '1px solid rgba(34, 211, 238, 0.3)', 
            borderRadius: '10px', width: '42px', height: '42px', 
            display: 'flex', alignItems: 'center', justifyContent: 'center' 
          }}>
            <span style={{ fontSize: '24px', fontWeight: '800', color: '#22D3EE' }}>L</span>
          </div>
          <span style={{ fontSize: '22px', fontWeight: '600', color: '#fff', letterSpacing: '-0.5px' }}>
            Lattice<span style={{ color: '#22D3EE' }}>mail</span>
          </span>
        </div>

        <h1 style={{ fontSize: '1.5rem', fontWeight: '600', marginBottom: '0.5rem', textAlign: 'center', color: 'var(--color-text)' }}>Welcome</h1>
        <p style={{ fontSize: '0.9rem', color: 'var(--color-muted)', marginBottom: '2rem', textAlign: 'center' }}>Authorized Access Only</p>

        <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div style={{ width: '100%' }}>
            <label style={{ fontSize: '0.875rem', color: 'var(--color-muted)', display: 'block', marginBottom: '0.5rem' }}>Identity Email</label>
            <input
              className="input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="user@latticemail.io"
              type="email"
              required
              style={{ width: '100%', boxSizing: 'border-box', padding: '0.75rem 1rem' }}
            />
          </div>

          <div style={{ width: '100%' }}>
            <label style={{ fontSize: '0.875rem', color: 'var(--color-muted)', display: 'block', marginBottom: '0.5rem' }}>Password</label>
            <input
              type="password"
              className="input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
              style={{ width: '100%', boxSizing: 'border-box', padding: '0.75rem 1rem' }}
            />
          </div>

          {err && <div style={{ padding: '0.75rem', background: 'rgba(239, 68, 68, 0.1)', color: '#fca5a5', borderRadius: '0.5rem', fontSize: '0.85rem' }}>{err}</div>}

          <button 
            className="btn-primary" 
            type="submit" 
            disabled={loading}
            style={{
              width: '100%', padding: '0.875rem', fontWeight: '600',
              background: 'linear-gradient(135deg, #22D3EE 0%, #3B82F6 100%)',
              border: 'none', borderRadius: '0.5rem', color: 'white'
            }}
          >
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>

        <div style={{ marginTop: '2rem', textAlign: 'center', fontSize: '0.9rem' }}>
          <span style={{ color: 'var(--color-muted)' }}>New to the platform?</span>{' '}
          <Link to="/register" style={{ color: '#22D3EE', textDecoration: 'none', fontWeight: '600' }}>Register Identity</Link>
        </div>
      </div>
    </div>
  );
}
