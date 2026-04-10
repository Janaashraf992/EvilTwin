import { useAlertStore } from "../../store/alertStore";
import { CountryFlag } from "../shared/CountryFlag";
import { ThreatBadge } from "../shared/ThreatBadge";
import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { generateMockAlert } from "../../api/mockData";

const SHOWCASE_MODE = import.meta.env.VITE_SHOWCASE_MODE === 'true';

function getRelativeTime(dateString: string) {
  const diffInSeconds = Math.floor((new Date().getTime() - new Date(dateString).getTime()) / 1000);
  if (diffInSeconds < 60) return `${diffInSeconds}s ago`;
  const diffInMinutes = Math.floor(diffInSeconds / 60);
  if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
  return new Date(dateString).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function ThreatFeed() {
  const alerts = useAlertStore((s) => s.alerts).slice(0, 100);
  const [, setTick] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setTick((t) => t + 1);
      // Generate active fake alerts for the showcase mode
      if (SHOWCASE_MODE && Math.random() > 0.3) {
        useAlertStore.getState().pushAlert(generateMockAlert());
      }
    }, 4000);
    return () => clearInterval(timer);
  }, []);

  return (
    <section className="glass rounded-xl p-4 shadow-panel flex flex-col h-[500px] max-h-[500px]">
      <div className="flex items-center gap-2 border-b border-border pb-3 mb-3 shrink-0">
        <div className="h-2 w-2 rounded-full bg-threat animate-pulse-dot" />
        <h3 className="font-display text-lg font-semibold tracking-wide text-text-primary">LIVE THREAT FEED</h3>
      </div>
      
      <div className="flex-1 overflow-y-auto pr-2 space-y-3">
        {alerts.length === 0 && <p className="text-sm text-text-muted italic">No live alerts actively streaming...</p>}
        <AnimatePresence initial={false}>
          {alerts.map((alert) => (
            <motion.article 
              key={alert.id} 
              initial={{ opacity: 0, height: 0, scale: 0.95, marginBottom: 0 }}
              animate={{ opacity: 1, height: "auto", scale: 1, marginBottom: 12 }}
              exit={{ opacity: 0, scale: 0.95, height: 0 }}
              transition={{ duration: 0.3 }}
              className={`rounded-lg border bg-surface/50 p-3 transition-colors duration-300
                ${alert.threat_level >= 3 ? "border-threat/50 bg-threat/10" : "border-border"}`}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <ThreatBadge level={alert.threat_level} />
                  <span className="text-xs text-text-muted">{getRelativeTime(alert.created_at)}</span>
                </div>
                <CountryFlag />
              </div>
              <p className="font-mono text-sm text-safe truncate">{alert.attacker_ip}</p>
              <p className="mt-1 text-sm text-text-primary/90 leading-snug">{alert.message}</p>
            </motion.article>
          ))}
        </AnimatePresence>
      </div>
    </section>
  );
}
