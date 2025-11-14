import React, { useState } from "react";
import { api } from "../lib/api";
import { useAuth } from "../state/auth";
import { useNavigate, useLocation, Link } from "react-router-dom";

export function Login() {
  const [email, setEmail] = useState("alice@example.com");
  const [password, setPassword] = useState("alicepass");
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
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '2rem'
    }}>
      <div style={{
        maxWidth: '440px',
        width: '100%',
        background: 'var(--color-surface)',
        borderRadius: '1.25rem',
        padding: '2.5rem',
        boxShadow: '0 20px 60px rgba(0, 0, 0, 0.4), 0 0 1px rgba(34, 211, 238, 0.1)',
        border: '1px solid rgba(255, 255, 255, 0.05)'
      }}>
        {/* Logo Section */}
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: '12px',
          marginBottom: '2rem',
          justifyContent: 'center'
        }}>
          <div style={{
            background: 'rgba(34, 211, 238, 0.1)',
            border: '1px solid rgba(34, 211, 238, 0.3)',
            borderRadius: '10px',
            width: '48px',
            height: '48px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <span style={{
              fontSize: '28px',
              fontWeight: '700',
              background: 'linear-gradient(135deg, #22D3EE 0%, #3B82F6 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text',
            }}>V</span>
          </div>
          <span style={{
            fontSize: '24px',
            fontWeight: '600',
            background: 'linear-gradient(135deg, #22D3EE 0%, #3B82F6 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text',
            letterSpacing: '0.5px'
          }}>ionyx</span>
        </div>

        <h1 style={{
          fontSize: '1.75rem',
          fontWeight: '600',
          marginBottom: '0.5rem',
          textAlign: 'center',
          color: 'var(--color-text)'
        }}>Welcome back</h1>
        
        <p style={{
          fontSize: '0.95rem',
          color: 'var(--color-muted)',
          marginBottom: '2rem',
          textAlign: 'center',
          lineHeight: '1.5'
        }}>Sign in to access your quantum-safe encrypted inbox</p>

        <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div>
            <label style={{
              fontSize: '0.875rem',
              color: 'var(--color-muted)',
              display: 'block',
              marginBottom: '0.5rem',
              fontWeight: '500'
            }}>Email Address</label>
            <input
              className="input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              type="email"
              required
              style={{
                fontSize: '0.95rem',
                padding: '0.75rem 1rem',
		width: '100%',  // Change this value
    maxWidth: '380px'
              }}
            />
          </div>

          <div>
            <label style={{
              fontSize: '0.875rem',
              color: 'var(--color-muted)',
              display: 'block',
              marginBottom: '0.5rem',
              fontWeight: '500'
            }}>Password</label>
            <input
              type="password"
              className="input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
              style={{
                fontSize: '0.95rem',
                padding: '0.75rem 1rem',
		width: '100%',  // Change this value
    maxWidth: '380px'
              }}
            />
          </div>

          {err && (
            <div style={{
              padding: '0.75rem 1rem',
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: '0.5rem',
              color: '#fca5a5',
              fontSize: '0.875rem'
            }}>
              {err}
            </div>
          )}

          <button 
            className="btn-primary" 
            type="submit"
            disabled={loading}
            style={{
              width: '100%',
              padding: '0.875rem',
              fontSize: '1rem',
              fontWeight: '600',
              marginTop: '0.5rem',
              opacity: loading ? 0.7 : 1,
              cursor: loading ? 'not-allowed' : 'pointer'
            }}
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        <div style={{
          marginTop: '2rem',
          paddingTop: '1.5rem',
          borderTop: '1px solid rgba(255, 255, 255, 0.05)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '0.5rem',
          fontSize: '0.9rem'
        }}>
          <span style={{ color: 'var(--color-muted)' }}>Don't have an account?</span>
          <Link 
            to="/register"
            style={{
              color: 'var(--color-accent)',
              textDecoration: 'none',
              fontWeight: '600',
              transition: 'color 150ms ease'
            }}
            onMouseEnter={(e) => e.currentTarget.style.color = '#22D3EE'}
            onMouseLeave={(e) => e.currentTarget.style.color = 'var(--color-accent)'}
          >
            Create account
          </Link>
        </div>

        <div style={{
          marginTop: '1.5rem',
          fontSize: '0.8rem',
          color: 'var(--color-muted)',
          textAlign: 'center',
          lineHeight: '1.5'
        }}>
          Protected by post-quantum cryptography. Need help?{' '}
          <Link 
            to="/help" 
            style={{
              color: 'var(--color-accent)',
              textDecoration: 'underline'
            }}
          >
            Documentation
          </Link>
        </div>
      </div>
    </div>
  );
}
