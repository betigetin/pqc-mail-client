import React from "react";
import { Outlet, Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../state/auth";

/**
 * Guard - route protection & layout wrapper for authenticated pages.
 * If not authenticated, navigates to /login while preserving location.
 * When authenticated, it renders the protected route inside a card container
 * and shows a small status row (device id).
 */

export function Guard() {
  const { token, deviceId } = useAuth();
  const loc = useLocation();
  if (!token) return <Navigate to="/login" state={{ from: loc }} replace />;

  return (
    <div className="app-container">
      {/* status row */}
      <div className="mb-4 flex items-center justify-between">
        <div className="text-sm text-muted">Device: <span style={{ color: "var(--color-text)" }}>{deviceId}</span></div>
        <div className="text-sm text-muted">Protected area</div>
      </div>

      {/* main card wrapper for protected routes */}
      <div className="card">
        <Outlet />
      </div>
    </div>
  );
}

