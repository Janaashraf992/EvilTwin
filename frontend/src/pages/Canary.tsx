import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Crosshair, Trash2, Copy, CheckCheck } from "lucide-react";
import {
  deleteCanaryToken,
  getCanaryTokens,
} from "../api/canary";
import type { CanaryToken } from "../api/canary";
import { useSessions } from "../hooks/useSessions";
import { SessionList } from "../components/sessions/SessionList";
import { SessionDetail } from "../components/sessions/SessionDetail";
import { useSession } from "../hooks/useSessions";
import { formatDate, formatDateTime } from "../utils/date";

function DifficultyBadge({ level }: { level: number }) {
  const styles: Record<number, string> = {
    0: "bg-slate-500/20 text-slate-300 border-slate-500/30",
    1: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
    2: "bg-amber-500/20 text-amber-300 border-amber-500/30",
    3: "bg-orange-500/20 text-orange-300 border-orange-500/30",
    4: "bg-red-500/20 text-red-300 border-red-500/30",
  };
  const labels: Record<number, string> = { 0: "Benign", 1: "Easy", 2: "Moderate", 3: "High", 4: "Critical" };
  return (
    <span className={`px-2 py-0.5 rounded-full border text-[10px] font-semibold uppercase tracking-wider ${styles[level] ?? styles[1]}`}>
      {labels[level] ?? level}
    </span>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button
      onClick={handleCopy}
      className="p-1.5 rounded text-white/40 hover:text-white hover:bg-white/10 transition"
      title="Copy webhook URL"
    >
      {copied ? <CheckCheck size={14} className="text-emerald-400" /> : <Copy size={14} />}
    </button>
  );
}

function TokenKindBadge({ kind }: { kind: string }) {
  const colors: Record<string, string> = {
    url: "bg-blue-500/20 text-blue-300 border-blue-500/30",
    file: "bg-amber-500/20 text-amber-300 border-amber-500/30",
    dns: "bg-purple-500/20 text-purple-300 border-purple-500/30",
    aws_key: "bg-orange-500/20 text-orange-300 border-orange-500/30",
    custom: "bg-slate-500/20 text-slate-300 border-slate-500/30",
  };
  return (
    <span className={`px-2 py-0.5 rounded-full border text-[10px] font-semibold uppercase tracking-wider ${colors[kind] ?? colors.custom}`}>
      {kind}
    </span>
  );
}

function TokenRow({ token }: { token: CanaryToken }) {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);

  const deleteMutation = useMutation({
    mutationFn: () => deleteCanaryToken(token.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["canary-tokens"] }),
  });

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className={`rounded-xl border p-4 transition ${
        token.is_active
          ? "border-white/10 bg-white/5"
          : "border-white/5 bg-white/[0.02] opacity-50"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-white truncate">{token.label}</span>
            <TokenKindBadge kind={token.token_kind} />
            <DifficultyBadge level={token.difficulty} />
            {!token.is_active && (
              <span className="text-[10px] text-white/30 uppercase tracking-wider">Revoked</span>
            )}
          </div>
          {token.description && (
            <p className="mt-0.5 text-xs text-white/40 truncate">{token.description}</p>
          )}
          <div className="mt-2 flex items-center gap-1">
            <code className="flex-1 truncate rounded bg-black/40 px-2 py-1 text-[11px] font-mono text-white/50">
              {token.webhook_url}{token.webhook_url?.includes('?') ? '&' : '?'}token_id={token.id}
            </code>
            <CopyButton text={`${token.webhook_url}${token.webhook_url?.includes('?') ? '&' : '?'}token_id=${token.id}`} />
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <div className="text-center">
            <p className={`text-xl font-bold tabular-nums ${token.trigger_count > 0 ? "text-red-400" : "text-white/30"}`}>
              {token.trigger_count}
            </p>
            <p className="text-[10px] text-white/30 uppercase tracking-wider">triggers</p>
          </div>
          <div className="text-center hidden sm:block">
            <p className="text-xs text-white/40">
              {token.last_triggered_at
                ? formatDate(token.last_triggered_at)
                : "Never"}
            </p>
            <p className="text-[10px] text-white/30 uppercase tracking-wider">last seen</p>
          </div>
          {token.is_active && (
            confirming ? (
              <div className="flex gap-1">
                <button
                  onClick={() => deleteMutation.mutate()}
                  className="px-2 py-1 rounded text-xs bg-red-600 text-white hover:bg-red-500 transition"
                >
                  Confirm
                </button>
                <button
                  onClick={() => setConfirming(false)}
                  className="px-2 py-1 rounded text-xs bg-white/10 text-white/60 hover:bg-white/20 transition"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <button
                onClick={() => setConfirming(true)}
                className="p-2 rounded-lg text-white/30 hover:text-red-400 hover:bg-red-500/10 transition"
                title="Revoke token"
              >
                <Trash2 size={15} />
              </button>
            )
          )}
        </div>
      </div>
      <p className="mt-2 text-[10px] text-white/25">
        Created {formatDateTime(token.created_at)} · ID: {token.id}
      </p>
    </motion.div>
  );
}

export function Canary() {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const { data: tokenData, isLoading } = useQuery({
    queryKey: ["canary-tokens"],
    queryFn: getCanaryTokens,
    refetchInterval: 30_000,
  });

  const { data: sessionsData } = useSessions({
    page: 1,
    page_size: 50,
    honeypot: "canary",
  });
  const { data: selectedSession } = useSession(selectedId);

  const tokens = tokenData?.items ?? [];
  const canarySessions = sessionsData?.items ?? [];
  const totalTriggers = tokens.reduce((sum: number, t: CanaryToken) => sum + t.trigger_count, 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/20">
            <Crosshair className="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Canary Tokens</h1>
            <p className="text-xs text-white/40">Script-managed honeytokens — monitored by the tripwire service</p>
          </div>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          { label: "Total Tokens", value: tokens.length },
          { label: "Active", value: tokens.filter((t: CanaryToken) => t.is_active).length },
          { label: "Total Triggers", value: totalTriggers },
          { label: "Sessions", value: canarySessions.length },
        ].map((card) => (
          <div key={card.label} className="rounded-xl border border-white/10 bg-white/5 p-4">
            <p className="text-2xl font-bold text-white tabular-nums">{card.value}</p>
            <p className="mt-0.5 text-xs text-white/40 uppercase tracking-wider">{card.label}</p>
          </div>
        ))}
      </div>

      {/* Deployed tokens list */}
      <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
        <h2 className="mb-3 text-sm font-semibold text-white/70 uppercase tracking-wider">
          Deployed Tokens
        </h2>
        {isLoading ? (
          <p className="text-sm text-white/40 py-6 text-center">Loading tokens…</p>
        ) : tokens.length === 0 ? (
          <div className="py-10 text-center">
            <Crosshair className="mx-auto mb-3 h-8 w-8 text-white/20" />
            <p className="text-sm text-white/40">No canary tokens deployed yet.</p>
            <p className="mt-1 text-xs text-white/25">
              Tokens are created via the tripwire script or API — see instructions below.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {tokens.map((token: CanaryToken) => (
              <TokenRow key={token.id} token={token} />
            ))}
          </div>
        )}
      </div>

      {/* Canary sessions feed */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div>
          <h2 className="mb-3 text-sm font-semibold text-white/70 uppercase tracking-wider">
            Recent Canary Events
          </h2>
          {canarySessions.length === 0 ? (
            <div className="rounded-xl border border-white/10 bg-white/5 py-10 text-center">
              <p className="text-sm text-white/40">No canary events yet.</p>
            </div>
          ) : (
            <SessionList
              sessions={canarySessions}
              selectedId={selectedId}
              onSelect={setSelectedId}
            />
          )}
        </div>
        {selectedSession && (
          <div>
            <h2 className="mb-3 text-sm font-semibold text-white/70 uppercase tracking-wider">
              Event Detail
            </h2>
            <SessionDetail session={selectedSession} />
          </div>
        )}
      </div>
    </div>
  );
}
