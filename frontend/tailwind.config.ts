import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        base: "rgb(var(--color-base) / <alpha-value>)",
        surface: "rgb(var(--color-surface) / <alpha-value>)",
        elevated: "rgb(var(--color-elevated) / <alpha-value>)",
        "text-primary": "rgb(var(--color-text-primary) / <alpha-value>)",
        "text-muted": "rgb(var(--color-text-muted) / <alpha-value>)",
        border: "rgb(var(--color-border) / <alpha-value>)",
        threat: "#E63946",
        safe: "#2EC4B6",
        warning: "#F4A261",
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
