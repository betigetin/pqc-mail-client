// simple base64 helpers for browser usage with small safety checks

export const b64e = (b: Uint8Array) => {
  try {
    let s = "";
    // chunk to avoid stack limits for very large arrays
    const CHUNK = 0x8000;
    for (let i = 0; i < b.length; i += CHUNK) {
      s += String.fromCharCode.apply(null, Array.prototype.slice.call(b, i, i + CHUNK));
    }
    return btoa(s);
  } catch (e) {
    // fallback: construct gradually
    let s = "";
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
  }
};

export const b64d = (s: string) => {
  try {
    const bin = atob(s);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  } catch (e) {
    // If invalid input, return empty array
    return new Uint8Array([]);
  }
};

export const utf8e = (s: string) => new TextEncoder().encode(s);
export const utf8d = (b: Uint8Array) => new TextDecoder().decode(b);

