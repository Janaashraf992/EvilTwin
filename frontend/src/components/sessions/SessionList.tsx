import type { SessionLog } from "../../types";
import { ThreatBadge } from "../shared/ThreatBadge";
import { formatDateTime } from "../../utils/date";

const HONEYPOT_COLORS: Record<string, string> = {
  cowrie: "bg-blue-500/15 text-blue-400 dark:text-blue-300 border-blue-500/25",
  dionaea: "bg-purple-500/15 text-purple-400 dark:text-purple-300 border-purple-500/25",
  canary: "bg-amber-500/15 text-amber-400 dark:text-amber-300 border-amber-500/25",
};

function HoneypotBadge({ honeypot }: { honeypot: string }) {
  const cls = HONEYPOT_COLORS[honeypot] ?? "bg-slate-500/15 text-text-muted border-slate-500/25";
  return (
    <span className={`px-1.5 py-0.5 rounded border text-[10px] font-semibold uppercase tracking-wide ${cls}`}>
      {honeypot}
    </span>
  );
}

export function SessionList({
  sessions,
  selectedId,
  onSelect
}: {
  sessions: SessionLog[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <section className="glass rounded-xl p-4 shadow-panel">
      <h3 className="font-display text-lg font-semibold text-text-primary">Sessions</h3>
      <div className="mt-3 space-y-2">
        {sessions.map((session) => (
          <button
            key={session.id}
            className={`w-full rounded-lg border p-3 text-left transition ${
              selectedId === session.id ? "border-safe/80 bg-safe/10" : "border-border/30 hover-theme"
            }`}
            onClick={() => onSelect(session.id)}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-sm text-safe">{session.attacker_ip}</span>
              <div className="flex items-center gap-1.5">
                <HoneypotBadge honeypot={session.honeypot} />
                <ThreatBadge level={session.threat_level} />
              </div>
            </div>
            <p className="mt-1 text-xs text-text-muted">{formatDateTime(session.start_time)}</p>
          </button>
        ))}
      </div>
    </section>
  );
}
