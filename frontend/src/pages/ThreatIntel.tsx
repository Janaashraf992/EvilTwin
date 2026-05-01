import { useStats } from "../hooks/useStats";

export function ThreatIntel() {
  const { data } = useStats();
  return (
    <section className="glass rounded-xl p-6 shadow-panel">
      <h2 className="font-display text-2xl font-semibold">Threat Intelligence Notes</h2>
      <p className="mt-2 text-slate-300">Top observed commands in the last 24 hours.</p>
      <ul className="mt-4 space-y-2">
        {(data?.top_commands ?? []).map((row) => (
          <li key={row.command} className="rounded border border-slate-700/40 bg-slate-900/50 p-3 font-mono text-sm text-cyan-200">
            {row.command} <span className="text-slate-400">x{row.count}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
