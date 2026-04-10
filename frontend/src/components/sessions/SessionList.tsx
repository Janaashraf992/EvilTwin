import type { SessionLog } from "../../types";
import { ThreatBadge } from "../shared/ThreatBadge";

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
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm text-cyan-200">{session.attacker_ip}</span>
              <ThreatBadge level={session.threat_level} />
            </div>
            <p className="mt-1 text-xs text-slate-400">{new Date(session.start_time).toLocaleString()}</p>
          </button>
        ))}
      </div>
    </section>
  );
}
