// front/src/lib/api.ts
const ENV_BASE = (import.meta.env as any).VITE_API_BASE_URL;
const API_BASE =
  ENV_BASE ||
  (typeof window !== "undefined" && window.location.hostname.includes("localhost")
    ? "http://localhost:5000"
    : window.location.origin);

async function jfetch<T>(
  path: string,
  opts: RequestInit & { token?: string } = {}
): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "Content-Type": "application/json",
    ...(opts.headers as any),
  };
  if (opts.token) headers["Authorization"] = `Bearer ${opts.token}`;

  const res = await fetch(`${API_BASE}/api${path}`, { ...opts, headers });

  if (res.status === 204) return {} as T;

  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!res.ok) {
    const msg =
      (data && (data.message || data.error || data.detail)) ||
      (typeof data === "string" ? data : `${res.status} ${res.statusText}`);
    throw new Error(msg);
  }

  return data as T;
}

export const api = {
  register(email: string, password: string) {
    return jfetch<{ email_hash: string }>("/register", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
  },

  login(email: string, password: string) {
    return jfetch<{ token: string }>("/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
  },

  // device_pubkeys contains X25519, Ed25519, and the large ML-KEM-768 keys
  uploadKeys(device_id: string, device_pubkeys: any, token: string) {
    return jfetch("/keys/upload", {
      method: "POST",
      token,
      body: JSON.stringify({ device_id, device_pubkeys }),
    });
  },

  fetchKeysByHash(email_hash: string) {
    return jfetch<{ devices: any[] }>(`/keys/${email_hash}`);
  },

  /**
   * payload: This is the encrypted ciphertext bundle.
   * In Latticemail, this contains: 
   * [Hybrid Ciphertext] + [PQ KEM Ciphertext] + [Classical DH Ciphertext]
   */
  sendMessage(to_user_hash: string, from_user_hash: string, payload: any, token: string) {
    return jfetch("/messages/send", {
      method: "POST",
      token,
      body: JSON.stringify({ to_user_hash, from_user_hash, payload }),
    });
  },

  inbox(token: string) {
    return jfetch<{ messages: any[] }>("/messages/inbox", {
      method: "POST", // Standardized to POST as per your Flask routes
      token,
      body: JSON.stringify({}),
    });
  },
};
