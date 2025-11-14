import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../state/auth";

export function Navbar() {
  const { token, logout, deviceId } = useAuth();
  const nav = useNavigate();
  
  return (
    <nav className="app-navbar">
      <div style={{ 
        maxWidth: '1280px', 
        margin: '0 auto', 
        width: '100%', 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between',
        gap: '2rem'
      }}>
        {/* LEFT: Logo + Brand */}
        <div style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>
          <Link to="/inbox" style={{ display: 'flex', alignItems: 'center', gap: '10px', textDecoration: 'none' }}>
            <div style={{
              background: 'rgba(34, 211, 238, 0.1)',
              border: '1px solid rgba(34, 211, 238, 0.3)',
              borderRadius: '8px',
              width: '40px',
              height: '40px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0
            }}>
              <span style={{
                fontSize: '24px',
                fontWeight: '700',
                background: 'linear-gradient(135deg, #22D3EE 0%, #3B82F6 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                backgroundClip: 'text',
              }}>V</span>
            </div>
            <span style={{
              fontSize: '20px',
              fontWeight: '600',
              background: 'linear-gradient(135deg, #22D3EE 0%, #3B82F6 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text',
              letterSpacing: '0.5px',
              whiteSpace: 'nowrap'
            }}>ionyx</span>
          </Link>
        </div>

        {/* CENTER: Nav tabs */}
        <div style={{ 
          position: 'absolute',
          left: '50%',
          transform: 'translateX(-50%)',
          display: 'flex',
          alignItems: 'center',
          gap: '2rem'
        }}>
          <Link to="/inbox" className="nav-link">Inbox</Link>
          <Link to="/compose" className="nav-link">Compose</Link>
          <Link to="/keys" className="nav-link">Device Keys</Link>
        </div>

        {/* RIGHT: Device + Auth */}
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: '1rem', 
          flexShrink: 0,
          marginLeft: 'auto'
        }}>
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '0.5rem' 
          }}>
            <span className="text-xs text-muted">Device:</span>
            <span className="text-sm font-medium" style={{ color: "var(--color-text)" }}>
              {deviceId}
            </span>
          </div>
          {!token ? (
            <>
              <Link className="nav-link" to="/login">Login</Link>
              <Link className="btn-primary register-btn" to="/register">Register</Link>
            </>
          ) : (
            <button
              onClick={() => { logout(); nav("/login"); }}
              className="btn-ghost logout-btn"
              aria-label="Logout"
            >
              Logout
            </button>
          )}
        </div>
      </div>
    </nav>
  );
}
