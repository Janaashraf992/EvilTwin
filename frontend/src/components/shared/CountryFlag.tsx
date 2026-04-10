const FLAGS: Record<string, string> = {
  US: "US",
  DE: "DE",
  CN: "CN",
  RU: "RU",
  FR: "FR"
};

export function CountryFlag({ country }: { country?: string }) {
  const code = (country || "??").toUpperCase();
  return <span className="rounded border border-slate-500/40 px-2 py-1 text-xs">{FLAGS[code] ?? code}</span>;
}
