import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // SOC dark theme palette
        base: "#0A0E1A",
        surface: "#101626",
        elevated: "#182038",
        threat: "#E63946",
        safe: "#2EC4B6",
        warning: "#F4A261",
        "text-primary": "#F1F5F9",
        "text-muted": "#94A3B8",
        border: "rgba(255, 255, 255, 0.08)",
      },
      fontFamily: {
        display: ["'JetBrains Mono'", "monospace"],
        body: ["'Inter'", "sans-serif"],
      },
      boxShadow: {
        panel: "0 16px 48px -12px rgba(0, 0, 0, 0.8)",
        glow: "0 0 24px rgba(230, 57, 70, 0.25)",
      },
      keyframes: {
        "slide-in": {
          "0%": { opacity: "0", transform: "translateY(-12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "pulse-dot": {
          "0%, 100%": { opacity: "1", transform: "scale(1)" },
          "50%": { opacity: "0.6", transform: "scale(1.4)" },
        },
        flash: {
          "0%": { backgroundColor: "rgba(230, 57, 70, 0.25)" },
          "100%": { backgroundColor: "transparent" },
        },
      },
      animation: {
        "slide-in": "slide-in 0.3s ease-out",
        "pulse-dot": "pulse-dot 2s ease-in-out infinite",
        flash: "flash 0.8s ease-out",
      },
    },
  },
  plugins: [],
} satisfies Config;
