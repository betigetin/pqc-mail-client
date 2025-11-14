import React, { useState } from "react";
import { api } from "../lib/api";
import { Link, useNavigate } from "react-router-dom";

export function Register() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [done, setDone] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const nav = useNavigate();

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setLoading(true);
    try {
      const r = await api.register(email, password);
      setDone(`Account created successfully!`);
      setTimeout(() => {
        nav("/login");
      }, 2000);
    } catch (e: any) {
      setErr(e?.message || "Registration failed");
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
        }}>Create your account</h1>
        
        <p style={{
          fontSize: '0.95rem',
          color: 'var(--color-muted)',
          marginBottom: '2rem',
          textAlign: 'center',
          lineHeight: '1.5'
        }}>Get started with quantum-safe encrypted messaging</p>

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
              placeholder="Choose a strong password"
              required
              style={{
                fontSize: '0.95rem',
                padding: '0.75rem 1rem',
		width: '100%',  // Change this value
    		maxWidth: '380px'
              }}
            />
            <p style={{
              fontSize: '0.8rem',
              color: 'var(--color-muted)',
              marginTop: '0.5rem'
            }}>Minimum 8 characters recommended</p>
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

          {done && (
            <div style={{
              padding: '0.75rem 1rem',
              background: 'rgba(34, 211, 238, 0.1)',
              border: '1px solid rgba(34, 211, 238, 0.3)',
              borderRadius: '0.5rem',
              color: '#22D3EE',
              fontSize: '0.875rem'
            }}>
              {done} Redirecting to login...
            </div>
          )}

          <button 
            className="btn-primary" 
            type="submit" 
            disabled={loading || !!done}
            style={{
              width: '100%',
              padding: '0.875rem',
              fontSize: '1rem',
              fontWeight: '600',
              marginTop: '0.5rem',
              opacity: (loading || done) ? 0.7 : 1,
              cursor: (loading || done) ? 'not-allowed' : 'pointer'
            }}
          >
            {loading ? 'Creating account...' : 'Create Account'}
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
          <span style={{ color: 'var(--color-muted)' }}>Already have an account?</span>
          <Link 
            to="/login"
            style={{
              color: 'var(--color-accent)',
              textDecoration: 'none',
              fontWeight: '600',
              transition: 'color 150ms ease'
            }}
            onMouseEnter={(e) => e.currentTarget.style.color = '#22D3EE'}
            onMouseLeave={(e) => e.currentTarget.style.color = 'var(--color-accent)'}
          >
            Sign in
          </Link>
        </div>

        <div style={{
          marginTop: '1.5rem',
          fontSize: '0.8rem',
          color: 'var(--color-muted)',
          textAlign: 'center',
          lineHeight: '1.5'
        }}>
          By creating an account, you agree to our terms of service and privacy policy.
        </div>
      </div>
    </div>
  );
}
