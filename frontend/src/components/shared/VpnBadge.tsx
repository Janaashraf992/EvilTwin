export function VpnBadge({ active }: { active: boolean }) {
  return (
    <span
      className={`rounded-md px-2 py-1 text-xs font-medium ${active ? "bg-emerald-600/30 text-emerald-300" : "bg-slate-600/30 text-slate-300"}`}
    >
      {active ? "VPN/Proxy" : "Direct"}
    </span>
  );
}
