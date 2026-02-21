import React from "react";
import { Outlet, Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../state/auth";

/**
 * Guard - Route protection & layout wrapper.
 * Ensures the "Latticemail" secure context is active before rendering children.
 */
export function Guard() {
  const { token, deviceId } = useAuth();
  const loc = useLocation();

  // Redirect to login if no token is present
  if (!token) {
    return <Navigate to="/login" state={{ from: loc }} replace />;
  }

  return (
    <div className="app-container" style={{ paddingTop: '2rem', paddingBottom: '4rem' }}>
      {/* Secure Session Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '1.5rem',
        padding: '0.5rem 1rem',
        background: 'rgba(34, 211, 238, 0.03)',
        borderLeft: '3px solid #22D3EE',
        borderRadius: '4px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{ 
            width: '8px', 
            height: '8px', 
            borderRadius: '50%', 
            background: '#22D3EE',
            boxShadow: '0 0 8px #22D3EE'
          }} />
          <span style={{ fontSize: '0.75rem', fontWeight: '600', color: 'var(--color-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Quantum Session Active
          </span>
        </div>
        
        <div style={{ fontSize: '0.75rem', color: 'var(--color-muted)', fontFamily: 'monospace' }}>
          Node: <span style={{ color: 'var(--color-text)' }}>{deviceId?.substring(0, 12)}...</span>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="card" style={{
        background: 'var(--color-surface)',
        borderRadius: '1rem',
        border: '1px solid rgba(255, 255, 255, 0.05)',
        boxShadow: '0 10px 30px rgba(0,0,0,0.2)',
        overflow: 'hidden'
      }}>
        <Outlet />
      </div>

      {/* Footer hint for the research paper */}
      <div style={{ 
        marginTop: '1.5rem', 
        textAlign: 'center', 
        fontSize: '0.7rem', 
        color: 'rgba(255,255,255,0.2)',
        letterSpacing: '0.5px'
      }}>
        END-TO-END ENCRYPTED VIA ML-KEM-768
      </div>
    </div>
  );
}
