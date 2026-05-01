import { PolarAngleAxis, PolarGrid, RadialBar, RadialBarChart, ResponsiveContainer } from "recharts";

function getThreatColor(level: number): string {
  if (level >= 4) return "#E63946"; // threat
  if (level === 3) return "#F4A261"; // warning
  if (level === 2) return "#E9C46A"; 
  if (level === 1) return "#2EC4B6"; // safe
  return "#6B7280"; // text-muted
}

export function ThreatLevelGauge({ level }: { level: number }) {
  const safeLevel = Number.isFinite(level) ? Math.min(Math.max(level, 0), 4) : 0;
  const data = [{ name: "level", value: safeLevel + 1, fill: getThreatColor(safeLevel) }];
  return (
    <section className="glass rounded-xl p-4 shadow-panel flex flex-col border-border/50 items-center justify-center h-full">
      <h3 className="font-display text-lg font-semibold tracking-wide text-text-primary text-center mb-2 w-full">PEAK THREAT (24H)</h3>
      <div className="h-48 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart innerRadius="60%" outerRadius="100%" data={data} startAngle={180} endAngle={0}>
            <PolarGrid gridType="circle" />
            <PolarAngleAxis type="number" domain={[0, 5]} tick={false} />
            <RadialBar dataKey="value" cornerRadius={10} background={{ fill: '#141928' }} />
          </RadialBarChart>
        </ResponsiveContainer>
      </div>
      <p className="text-center text-sm font-mono text-text-muted mt-[-2rem]">
        LEVEL <span className="font-bold text-white text-base">{safeLevel}</span> / 4
      </p>
    </section>
  );
}
