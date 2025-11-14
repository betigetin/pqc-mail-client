import React, { createContext, useContext, useMemo, useState } from "react";

type AuthCtx = {
  token: string | null;
  setToken: (t: string | null) => void;
  logout: () => void;
  deviceId: string;
  setDeviceId: (id: string) => void;
};

const Ctx = createContext<AuthCtx | null>(null);

const DEVICE_KEY = "pqmail_deviceId";
const TOKEN_KEY = "jwt";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setTokenState] = useState<string | null>(
    localStorage.getItem(TOKEN_KEY) || null
  );

  const [deviceId, setDeviceIdState] = useState<string>(
    localStorage.getItem(DEVICE_KEY) || "web-01"
  );

  const setToken = (t: string | null) => {
    setTokenState(t);
    if (t) localStorage.setItem(TOKEN_KEY, t);
    else localStorage.removeItem(TOKEN_KEY);
  };

  const setDeviceId = (id: string) => {
    setDeviceIdState(id);
    if (id) localStorage.setItem(DEVICE_KEY, id);
    else localStorage.removeItem(DEVICE_KEY);
  };

  const logout = () => setToken(null);

  const value = useMemo(() => ({ token, setToken, logout, deviceId, setDeviceId }), [token, deviceId]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAuth outside provider");
  return ctx;
}

