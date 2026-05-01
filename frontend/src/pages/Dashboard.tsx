import { motion } from "framer-motion";
import { useSessions } from "../hooks/useSessions";
import { useStats } from "../hooks/useStats";
import { AttackVolumeChart } from "../components/dashboard/AttackVolumeChart";
import { GeoAttackMap } from "../components/dashboard/GeoAttackMap";
import { StatCard } from "../components/dashboard/StatCard";
import { ThreatFeed } from "../components/dashboard/ThreatFeed";
import { ThreatLevelGauge } from "../components/dashboard/ThreatLevelGauge";
import { TopAttackerTable } from "../components/dashboard/TopAttackerTable";
import { Activity, ShieldAlert, Users, Network } from "lucide-react";

const container = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1
    }
  }
};

const item = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { duration: 0.4 } }
};

export function Dashboard() {
  const { data: stats } = useStats();
  const { data: sessionsData } = useSessions({ page: 1, page_size: 25 });
  const sessions = sessionsData?.items ?? [];
  const peakThreatLevel = sessions.reduce((maxLevel, session) => {
    return Math.max(maxLevel, session.threat_level);
  }, 0);

  return (
    <motion.div 
      className="space-y-4"
      variants={container}
      initial="hidden"
      animate="show"
    >
      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <motion.div variants={item}><StatCard label="Sessions 24h" value={stats?.total_sessions_24h ?? 0} icon={<Activity size={20} />} /></motion.div>
        <motion.div variants={item}><StatCard label="Unique IPs" value={stats?.unique_attackers_24h ?? 0} icon={<Users size={20} />} /></motion.div>
        <motion.div variants={item}><StatCard label="Critical Alerts" value={stats?.critical_alerts_24h ?? 0} icon={<ShieldAlert size={20} className="text-threat" />} /></motion.div>
        <motion.div variants={item}><StatCard label="VPN Users" value={sessions.filter((s) => s.vpn_detected).length} icon={<Network size={20} />} /></motion.div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <motion.div variants={item} className="space-y-4 xl:col-span-2">
          <AttackVolumeChart data={stats?.attacks_by_hour ?? []} />
          <TopAttackerTable sessions={sessions} />
        </motion.div>
        <motion.div variants={item} className="space-y-4 flex flex-col h-full">
          <ThreatLevelGauge level={peakThreatLevel} />
          <div className="flex-grow min-h-0">
             <ThreatFeed />
          </div>
        </motion.div>
      </div>

      <motion.div variants={item}>
        <GeoAttackMap sessions={sessions} />
      </motion.div>
    </motion.div>
  );
}
