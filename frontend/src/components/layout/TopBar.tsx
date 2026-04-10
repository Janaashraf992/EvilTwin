import { useWebSocket } from "../../hooks/useWebSocket";

const WS_URL = import.meta.env.VITE_WS_URL ?? "ws://localhost:8000/ws/alerts";

export function TopBar() {
  const { connected, lastPing, retryCount, nextRetryInMs, lastError } = useWebSocket(WS_URL);

  return (
    <header className="glass-elevated flex items-center justify-between rounded-xl px-6 py-4 shadow-panel border-border/50">
      <div>
        <h2 className="font-display text-xl font-semibold tracking-wide text-text-primary">LIVE THREAT OPERATIONS</h2>
        <p className="text-sm text-text-muted mt-0.5">Real-time analyst view across deception infrastructure</p>
      </div>
      <div className="text-right flex flex-col items-end">
        <div className="flex items-center gap-2 bg-[#0A0E1A] px-3 py-1.5 rounded-full border border-border/50">
          <div className={`h-2 w-2 rounded-full ${connected ? "bg-safe animate-pulse-dot" : "bg-threat"}`} />
          <span className={`text-xs font-mono uppercase tracking-wider ${connected ? "text-safe" : "text-threat"}`}>
            {connected ? "Stream Active" : "Disconnected"}
          </span>
        </div>
        <div className="mt-2 text-xs text-text-muted font-mono">
          {lastPing ? `Last Event: ${lastPing.toLocaleTimeString()}` : "Awaiting transmission..."}
        </div>
        {!connected && retryCount > 0 && (
          <p className="mt-1 flex text-xs text-warning opacity-80">
            {lastError ? `${lastError} • ` : ""}
            Retries: {retryCount}
            {nextRetryInMs ? ` • Next: ${Math.ceil(nextRetryInMs / 1000)}s` : ""}
          </p>
        )}
      </div>
    </header>
  );
}
