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
    <div className="min-h-screen">
      <Navbar />
      <main className="app-container">
        <Routes>
          <Route path="/" element={<Navigate to="/inbox" replace />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          <Route element={<Guard />}>
            <Route path="/inbox" element={<Inbox />} />
            <Route path="/keys" element={<Keys />} />
            <Route path="/compose" element={<Compose />} />
          </Route>

          <Route
            path="*"
            element={
              <div className="card max-w-md mx-auto text-center">
                <h2 className="text-xl font-semibold mb-2">404 — Not Found</h2>
                <p className="text-sm text-muted">The page you requested doesn't exist.</p>
              </div>
            }
          />
        </Routes>
      </main>
    </div>
  );
}

