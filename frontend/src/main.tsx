import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";

import App from "./App";
import { useThemeStore } from "./store/themeStore";
import "./index.css";

const queryClient = new QueryClient();

function ThemeInitializer({ children }: { children: React.ReactNode }) {
  const theme = useThemeStore((s) => s.theme);
  const html = document.documentElement;
  html.classList.remove("dark", "light");
  html.classList.add(theme);
  return <>{children}</>;
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <ThemeInitializer>
          <App />
        </ThemeInitializer>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>
);
