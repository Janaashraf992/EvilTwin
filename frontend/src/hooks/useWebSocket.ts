import { useEffect, useRef, useState } from "react";

import { useAlertStore } from "../store/alertStore";
import { useAuthStore } from "../store/authStore";

export function useWebSocket(url: string) {
  const [connected, setConnected] = useState(false);
  const [lastPing, setLastPing] = useState<Date | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const [nextRetryInMs, setNextRetryInMs] = useState<number | null>(null);
  const [lastError, setLastError] = useState<string | null>(null);
  const pushAlert = useAlertStore((s) => s.pushAlert);
  const reconnectDelay = useRef(1000);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let timer: number | undefined;

    const connect = () => {
      const token = useAuthStore.getState().accessToken;
      const wsUrl = token ? `${url}?token=${encodeURIComponent(token)}` : url;
      ws = new WebSocket(wsUrl);
      ws.onopen = () => {
        setConnected(true);
        setRetryCount(0);
        setNextRetryInMs(null);
        setLastError(null);
        reconnectDelay.current = 1000;
      };
      ws.onmessage = (ev) => {
        setLastPing(new Date());
        try {
          pushAlert(JSON.parse(ev.data));
        } catch {
          // ignore invalid payloads
        }
      };
      ws.onerror = () => {
        setConnected(false);
        setLastError("Connection error");
      };
      ws.onclose = () => {
        setConnected(false);
        setRetryCount((prev) => prev + 1);
        setNextRetryInMs(reconnectDelay.current);
        timer = window.setTimeout(connect, reconnectDelay.current);
        reconnectDelay.current = Math.min(reconnectDelay.current * 2, 30_000);
      };
    };

    connect();

    return () => {
      if (timer) {
        clearTimeout(timer);
      }
      ws?.close();
    };
  }, [url, pushAlert]);

  return { connected, lastPing, retryCount, nextRetryInMs, lastError };
}
