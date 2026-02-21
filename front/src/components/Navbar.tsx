import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../state/auth";

export function Navbar() {
  const { token, logout, deviceId } = useAuth();
  const nav = useNavigate();
  
  return (
    <nav className="app-navbar" style={{
      borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
      background: 'rgba(10, 10, 10, 0.8)',
      backdropFilter: 'blur(12px)',
      position: 'sticky',
      top: 0,
      zIndex: 100,
      padding: '0.75rem 2rem'
    }}>
      <div style={{ 
        maxWidth: '1280px', 
        margin: '0 auto', 
        width: '100%', 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between'
      }}>
        
        {/* LEFT: Logo + Brand */}
        <div style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>
          <Link to="/inbox" style={{ display: 'flex', alignItems: 'center', gap: '10px', textDecoration: 'none' }}>
            <div style={{
              background: 'rgba(34, 211, 238, 0.1)',
              border: '1px solid rgba(34, 211, 238, 0.3)',
              borderRadius: '8px',
              width: '36px',
              height: '36px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <span style={{
                fontSize: '20px',
                fontWeight: '800',
                color: '#22D3EE'
              }}>L</span>
            </div>
            <span style={{
              fontSize: '18px',
              fontWeight: '600',
              color: '#fff',
              letterSpacing: '-0.3px'
            }}>
              Lattice<span style={{ color: '#22D3EE' }}>mail</span>
            </span>
          </Link>
        </div>

        {/* CENTER: Nav tabs (Visible only if logged in for cleaner UI) */}
        {token && (
          <div style={{ 
            display: 'flex',
            alignItems: 'center',
            gap: '1.5rem',
            background: 'rgba(255,255,255,0.03)',
            padding: '4px 16px',
            borderRadius: '20px',
            border: '1px solid rgba(255,255,255,0.05)'
          }}>
            <Link to="/inbox" className="nav-link" style={{ fontSize: '0.9rem' }}>Inbox</Link>
            <Link to="/compose" className="nav-link" style={{ fontSize: '0.9rem' }}>Compose</Link>
            <Link to="/keys" className="nav-link" style={{ fontSize: '0.9rem' }}>Security</Link>
          </div>
        )}

        {/* RIGHT: Device + Auth */}
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: '1.25rem'
        }}>
          {token && (
            <div style={{ 
              display: 'flex', 
              flexDirection: 'column',
              alignItems: 'flex-end'
            }}>
              <span style={{ fontSize: '10px', color: 'var(--color-muted)', textTransform: 'uppercase' }}>Secure Node</span>
              <span style={{ fontSize: '12px', fontFamily: 'monospace', color: '#22D3EE' }}>
                {deviceId?.substring(0, 8)}...
              </span>
            </div>
          )}

          {!token ? (
            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <Link className="nav-link" to="/login">Login</Link>
              <Link className="btn-primary" to="/register" style={{ padding: '0.5rem 1rem', fontSize: '0.85rem' }}>Get Started</Link>
            </div>
          ) : (
            <button
              onClick={() => { logout(); nav("/login"); }}
              className="btn-ghost"
              style={{
                fontSize: '0.85rem',
                color: '#fca5a5',
                padding: '0.5rem 0.75rem'
              }}
            >
              Logout
            </button>
          )}
        </div>
      </div>
    </nav>
  );
}
