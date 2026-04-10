import { useState } from "react";

import { SessionDetail } from "../components/sessions/SessionDetail";
import { SessionList } from "../components/sessions/SessionList";
import { useSession, useSessions } from "../hooks/useSessions";

export function Sessions() {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [threatLevel, setThreatLevel] = useState<string>("");
  const [honeypot, setHoneypot] = useState<string>("");
  const [ip, setIp] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const { data } = useSessions({
    page,
    page_size: pageSize,
    threat_level: threatLevel ? Number(threatLevel) : undefined,
    honeypot: honeypot || undefined,
    ip: ip || undefined,
    date_from: dateFrom || undefined,
    date_to: dateTo || undefined
  });
  const { data: selectedSession } = useSession(selectedId);

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div>
        <section className="glass mb-4 grid grid-cols-1 gap-2 rounded-xl p-3 md:grid-cols-2">
          <input
            value={ip}
            onChange={(e) => {
              setPage(1);
              setIp(e.target.value);
            }}
            placeholder="Filter by IP"
            className="rounded border border-slate-700 bg-slate-900/60 px-3 py-2 text-sm"
          />
          <select
            value={threatLevel}
            onChange={(e) => {
              setPage(1);
              setThreatLevel(e.target.value);
            }}
            className="rounded border border-slate-700 bg-slate-900/60 px-3 py-2 text-sm"
          >
            <option value="">All threat levels</option>
            <option value="0">0</option>
            <option value="1">1</option>
            <option value="2">2</option>
            <option value="3">3</option>
            <option value="4">4</option>
          </select>
          <select
            value={honeypot}
            onChange={(e) => {
              setPage(1);
              setHoneypot(e.target.value);
            }}
            className="rounded border border-slate-700 bg-slate-900/60 px-3 py-2 text-sm"
          >
            <option value="">All honeypots</option>
            <option value="cowrie">cowrie</option>
            <option value="dionaea">dionaea</option>
            <option value="canary">canary</option>
          </select>
          <select
            value={String(pageSize)}
            onChange={(e) => {
              setPage(1);
              setPageSize(Number(e.target.value));
            }}
            className="rounded border border-slate-700 bg-slate-900/60 px-3 py-2 text-sm"
          >
            <option value="10">10 / page</option>
            <option value="25">25 / page</option>
            <option value="50">50 / page</option>
          </select>
          <input
            value={dateFrom}
            onChange={(e) => {
              setPage(1);
              setDateFrom(e.target.value);
            }}
            type="datetime-local"
            className="rounded border border-slate-700 bg-slate-900/60 px-3 py-2 text-sm"
          />
          <input
            value={dateTo}
            onChange={(e) => {
              setPage(1);
              setDateTo(e.target.value);
            }}
            type="datetime-local"
            className="rounded border border-slate-700 bg-slate-900/60 px-3 py-2 text-sm"
          />
        </section>
        <SessionList sessions={data?.items ?? []} selectedId={selectedId} onSelect={setSelectedId} />
        <div className="mt-3 flex items-center gap-2">
          <button
            className="glass rounded px-3 py-1 text-sm"
            disabled={(data?.page ?? page) <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            Prev
          </button>
          <span className="text-sm text-slate-300">Page {data?.page ?? page} / {data?.pages ?? 1}</span>
          <button
            className="glass rounded px-3 py-1 text-sm"
            disabled={(data?.page ?? page) >= (data?.pages ?? 1)}
            onClick={() => setPage((p) => p + 1)}
          >
            Next
          </button>
        </div>
      </div>
      <SessionDetail session={selectedSession ?? null} />
    </div>
  );
}
