import React, { createContext, useContext, useMemo, useState, useEffect } from "react";

type AuthCtx = {
  token: string | null;
  setToken: (t: string | null) => void;
  logout: () => void;
  deviceId: string;
  setDeviceId: (id: string) => void;
};

const Ctx = createContext<AuthCtx | null>(null);

const DEVICE_KEY = "latticemail_device_id";
const TOKEN_KEY = "latticemail_jwt";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  // Initialize state from localStorage
  const [token, setTokenState] = useState<string | null>(
    localStorage.getItem(TOKEN_KEY) || null
  );

  const [deviceId, setDeviceIdState] = useState<string>(() => {
    const saved = localStorage.getItem(DEVICE_KEY);
    if (saved) return saved;
    // Generate a pseudo-random node ID for the research demo if none exists
    const newId = `node-${Math.random().toString(36).substring(2, 9)}`;
    localStorage.setItem(DEVICE_KEY, newId);
    return newId;
  });

  // Effect to sync logout/login across multiple browser tabs
  useEffect(() => {
    const syncAuth = (e: StorageEvent) => {
      if (e.key === TOKEN_KEY) {
        setTokenState(e.newValue);
      }
    };
    window.addEventListener("storage", syncAuth);
    return () => window.removeEventListener("storage", syncAuth);
  }, []);

  const setToken = (t: string | null) => {
    setTokenState(t);
    if (t) {
      localStorage.setItem(TOKEN_KEY, t);
    } else {
      localStorage.removeItem(TOKEN_KEY);
    }
  };

  const setDeviceId = (id: string) => {
    setDeviceIdState(id);
    localStorage.setItem(DEVICE_KEY, id);
  };

  const logout = () => {
    setToken(null);
  };

  const value = useMemo(
    () => ({ token, setToken, logout, deviceId, setDeviceId }),
    [token, deviceId]
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
