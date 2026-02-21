import { Routes, Route, Navigate } from "react-router-dom";
import { Navbar } from "./components/Navbar";
import { Login } from "./pages/Login";
import { Register } from "./pages/Register";
import { Inbox } from "./pages/Inbox";
import { Keys } from "./pages/Keys";
import { Compose } from "./pages/Compose";
import { Guard } from "./components/Guard";

export default function App() {
  return (
    <div className="min-h-screen" style={{ display: 'flex', flexDirection: 'column' }}>
      <Navbar />
      
      {/* Note: app-container is removed from here because Login/Register 
          provide their own full-screen centered layouts, and Guard 
          provides the container for protected pages.
      */}
      <main style={{ flex: 1, position: 'relative' }}>
        <Routes>
          <Route path="/" element={<Navigate to="/inbox" replace />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          {/* Protected Routes Enclave */}
          <Route element={<Guard />}>
            <Route path="/inbox" element={<Inbox />} />
            <Route path="/keys" element={<Keys />} />
            <Route path="/compose" element={<Compose />} />
          </Route>

          {/* Clean 404 Page */}
          <Route
            path="*"
            element={
              <div style={{ 
                display: 'flex', alignItems: 'center', justifyContent: 'center', 
                height: '80vh', textAlign: 'center' 
              }}>
                <div className="card" style={{ maxWidth: '320px', border: '1px solid rgba(255,255,255,0.05)' }}>
                  <h2 style={{ fontSize: '1.25rem', fontWeight: '600', marginBottom: '0.5rem', color: '#fca5a5' }}>
                    404 — Access Denied
                  </h2>
                  <p style={{ fontSize: '0.85rem', color: 'var(--color-muted)' }}>
                    The requested node does not exist or has been moved.
                  </p>
                </div>
              </div>
            }
          />
        </Routes>
      </main>
    </div>
  );
}
