import type { SessionLog } from "../../types";
import { ThreatBadge } from "../shared/ThreatBadge";

const HONEYPOT_COLORS: Record<string, string> = {
  cowrie: "bg-blue-500/15 text-blue-300 border-blue-500/25",
  dionaea: "bg-purple-500/15 text-purple-300 border-purple-500/25",
  canary: "bg-amber-500/15 text-amber-300 border-amber-500/25",
};

function HoneypotBadge({ honeypot }: { honeypot: string }) {
  const cls = HONEYPOT_COLORS[honeypot] ?? "bg-slate-500/15 text-slate-300 border-slate-500/25";
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
      <h3 className="font-display text-lg font-semibold">Sessions</h3>
      <div className="mt-3 space-y-2">
        {sessions.map((session) => (
          <button
            key={session.id}
            className={`w-full rounded-lg border p-3 text-left transition ${
              selectedId === session.id ? "border-cyan-400/80 bg-cyan-500/10" : "border-slate-700/40 bg-slate-900/40"
            }`}
            onClick={() => onSelect(session.id)}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-sm text-cyan-200">{session.attacker_ip}</span>
              <div className="flex items-center gap-1.5">
                <HoneypotBadge honeypot={session.honeypot} />
                <ThreatBadge level={session.threat_level} />
              </div>
            </div>
            <p className="mt-1 text-xs text-slate-400">{new Date(session.start_time).toLocaleString()}</p>
          </button>
        ))}
      </div>
    </section>
  );
}
