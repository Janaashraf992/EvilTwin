function currentLocation(): URL {
  if (typeof window === "undefined") {
    return new URL("http://localhost:3000/");
  }

  return new URL(window.location.href);
}

export function resolveApiBaseUrl(): string {
  const configuredUrl = import.meta.env.VITE_API_BASE_URL?.trim();
  if (configuredUrl) {
    return configuredUrl.replace(/\/$/, "");
  }

  const url = currentLocation();
  url.protocol = url.protocol === "https:" ? "https:" : "http:";
  url.port = "8000";
  url.pathname = "/";
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/$/, "");
}

export function resolveAlertsWebSocketUrl(): string {
  const configuredUrl = import.meta.env.VITE_WS_URL?.trim();
  if (configuredUrl) {
    return configuredUrl;
  }

  const url = currentLocation();
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.port = "8000";
  url.pathname = "/ws/alerts";
  url.search = "";
  url.hash = "";
  return url.toString();
}