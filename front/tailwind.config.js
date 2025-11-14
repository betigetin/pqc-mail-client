/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Theme 1 — Cyber Minimal
        primary: "#3B82F6",       // blue-500
        "primary-dark": "#1E40AF",// blue-900
        accent: "#22D3EE",        // cyan-400
        bg: "#0F172A",            // slate-900
        surface: "#1E293B",       // slate-800
        text: "#F8FAFC",          // slate-50
        muted: "#94A3B8",         // slate-400
      },
      boxShadow: {
        glow: "0 8px 30px rgba(34,211,238,0.08)",
        soft: "0 6px 18px rgba(2,6,23,0.6)",
      },
      borderRadius: {
        xl: "1rem",
      },
    },
  },
  plugins: [],
};

