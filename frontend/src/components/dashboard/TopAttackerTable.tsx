import type { SessionLog } from "../../types";
import { ThreatBadge } from "../shared/ThreatBadge";
import { useState, useMemo } from "react";

export function TopAttackerTable({ sessions }: { sessions: SessionLog[] }) {
  const [page, setPage] = useState(1);
  const [sortField, setSortField] = useState<keyof SessionLog>("start_time");
  const [sortDesc, setSortDesc] = useState(true);

  const PAGE_SIZE = 5;

  const handleSort = (field: keyof SessionLog) => {
    if (sortField === field) setSortDesc(!sortDesc);
    else { setSortField(field); setSortDesc(true); }
  };

  const sortedSessions = useMemo(() => {
    return [...sessions].sort((a, b) => {
      let aVal = a[sortField];
      let bVal = b[sortField];
      if (typeof aVal === "string" && typeof bVal === "string") {
        return sortDesc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
      }
      if (typeof aVal === "number" && typeof bVal === "number") {
        return sortDesc ? bVal - aVal : aVal - bVal;
      }
      return 0;
    });
  }, [sessions, sortField, sortDesc]);

  const totalPages = Math.ceil(sortedSessions.length / PAGE_SIZE) || 1;
  const paginatedRows = sortedSessions.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  return (
    <section className="glass rounded-xl p-4 shadow-panel flex flex-col h-full">
      <h3 className="font-display text-lg font-semibold tracking-wide text-text-primary mb-3">TOP ATTACKERS</h3>
      <div className="flex-1 overflow-x-auto">
        <table className="w-full text-left text-sm border-collapse">
          <thead>
            <tr className="text-text-muted border-b border-border/50">
              <th className="pb-2 cursor-pointer hover:text-white" onClick={() => handleSort("attacker_ip")}>IP {sortField === "attacker_ip" && (sortDesc ? "▼" : "▲")}</th>
              <th className="pb-2 cursor-pointer hover:text-white" onClick={() => handleSort("threat_level")}>Threat {sortField === "threat_level" && (sortDesc ? "▼" : "▲")}</th>
              <th className="pb-2 cursor-pointer hover:text-white" onClick={() => handleSort("honeypot")}>Honeypot {sortField === "honeypot" && (sortDesc ? "▼" : "▲")}</th>
              <th className="pb-2 cursor-pointer hover:text-white" onClick={() => handleSort("start_time")}>Last Seen {sortField === "start_time" && (sortDesc ? "▼" : "▲")}</th>
            </tr>
          </thead>
          <tbody>
            {paginatedRows.map((s) => (
              <tr key={s.id} className="border-b border-border/30 hover:bg-surface/50 transition-colors">
                <td className="py-3 font-mono text-safe">{s.attacker_ip}</td>
                <td className="py-3"><ThreatBadge level={s.threat_level} /></td>
                <td className="py-3 text-text-primary/80">{s.honeypot}</td>
                <td className="py-3 text-text-muted">{new Date(s.start_time).toLocaleString()}</td>
              </tr>
            ))}
            {paginatedRows.length === 0 && (
              <tr><td colSpan={4} className="py-4 text-center text-text-muted italic">No data available</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="mt-4 flex justify-between items-center text-xs text-text-muted">
        <span>Page {page} of {totalPages}</span>
        <div className="space-x-2">
          <button 
            onClick={() => setPage(p => Math.max(1, p - 1))} 
            disabled={page === 1}
            className="px-2 py-1 glass-elevated rounded disabled:opacity-50 hover:bg-surface/80 transition-colors"
          >Prev</button>
          <button 
            onClick={() => setPage(p => Math.min(totalPages, p + 1))} 
            disabled={page === totalPages}
            className="px-2 py-1 glass-elevated rounded disabled:opacity-50 hover:bg-surface/80 transition-colors"
          >Next</button>
        </div>
      </div>
    </section>
  );
}
