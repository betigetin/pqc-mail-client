export async function sha256Hex(msg: string) {
  const data = new TextEncoder().encode(msg);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const hex = [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return hex;
}

