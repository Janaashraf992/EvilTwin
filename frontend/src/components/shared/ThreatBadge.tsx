const LEVELS: Record<number, { label: string; classes: string }> = {
  0: { label: "Unknown", classes: "bg-slate-500" },
  1: { label: "Low", classes: "bg-sky-500" },
  2: { label: "Medium", classes: "bg-amber-500" },
  3: { label: "High", classes: "bg-orange-500" },
  4: { label: "Critical", classes: "bg-red-500" }
};

export function ThreatBadge({ level }: { level: number }) {
  const cfg = LEVELS[level] ?? LEVELS[0];
  return <span className={`rounded-full px-2 py-1 text-xs font-semibold text-white ${cfg.classes}`}>{cfg.label}</span>;
}
