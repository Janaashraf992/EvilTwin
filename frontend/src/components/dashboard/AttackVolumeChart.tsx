import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export function AttackVolumeChart({ data }: { data: Array<{ hour: number; count: number }> }) {
  return (
    <section className="glass rounded-xl p-4 shadow-panel flex flex-col border-border/50">
      <h3 className="font-display text-lg font-semibold tracking-wide text-text-primary mb-3">ACTIVITY TIMELINE (24H)</h3>
      <div className="h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <XAxis dataKey="hour" stroke="#6B7280" tick={{ fill: '#6B7280', fontSize: 12 }} tickMargin={10} />
            <YAxis stroke="#6B7280" tick={{ fill: '#6B7280', fontSize: 12 }} />
            <Tooltip 
              contentStyle={{ backgroundColor: '#0F1424', borderColor: 'rgba(255,255,255,0.07)', color: '#E8EAF0' }}
              itemStyle={{ color: '#2EC4B6' }}
            />
            <Area type="monotone" dataKey="count" stroke="#2EC4B6" fillOpacity={1} fill="url(#colorCount)" />
            <defs>
              <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#2EC4B6" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="#2EC4B6" stopOpacity={0}/>
              </linearGradient>
            </defs>
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
