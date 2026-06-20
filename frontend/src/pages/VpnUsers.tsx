import { motion } from "framer-motion";
import { useVpnUsers } from "../hooks/useVpnUsers";
import { Shield, Globe, MapPin, Clock } from "lucide-react";
import { formatDateTime } from "../utils/date";

const container = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: {
      staggerChildren: 0.05
    }
  }
};

const item = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { duration: 0.3 } }
};

function ThreatBadgeLocal({ level }: { level: number }) {
  const colors: Record<number, string> = {
    0: "bg-slate-500/20 text-text-muted",
    1: "bg-emerald-500/20 text-emerald-400",
    2: "bg-yellow-500/20 text-yellow-400",
    3: "bg-orange-500/20 text-orange-400",
    4: "bg-red-500/20 text-red-400",
  };
  const labels: Record<number, string> = {
    0: "Unknown",
    1: "Low",
    2: "Medium",
    3: "High",
    4: "Critical",
  };
  return (
    <span className={`px-2 py-1 rounded-full text-xs font-medium ${colors[level] ?? colors[0]}`}>
      {labels[level] ?? "Unknown"}
    </span>
  );
}

export function VpnUsers() {
  const { data: vpnUsers, isLoading, error } = useVpnUsers();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass rounded-xl p-6 text-center">
        <p className="text-red-400">Failed to load VPN users</p>
      </div>
    );
  }

  return (
    <motion.div
      className="space-y-4"
      variants={container}
      initial="hidden"
      animate="show"
    >
      <motion.div variants={item} className="flex items-center gap-3 mb-6">
        <div className="p-3 bg-gradient-to-br from-cyan-500/20 to-blue-500/20 rounded-xl border border-cyan-500/20">
          <Globe className="w-6 h-6 text-cyan-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-text-primary">VPN Users</h1>
          <p className="text-sm text-text-muted">Detected VPN connections in the last 24 hours</p>
        </div>
      </motion.div>

      <motion.div variants={item} className="glass rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border/50">
                <th className="px-6 py-4 text-left text-xs font-semibold text-text-muted uppercase tracking-wider">IP Address</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-text-muted uppercase tracking-wider">Location</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-text-muted uppercase tracking-wider">ISP</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-text-muted uppercase tracking-wider">Sessions</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-text-muted uppercase tracking-wider">Threat</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-text-muted uppercase tracking-wider">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/30">
              {vpnUsers?.map((user) => (
                <tr key={user.ip} className="hover:bg-surface/50 transition-colors">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-cyan-500/10 rounded-lg">
                        <Shield className="w-4 h-4 text-cyan-400" />
                      </div>
                      <span className="font-mono text-sm text-text-primary">{user.ip}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <MapPin className="w-4 h-4 text-text-muted" />
                      <span className="text-sm text-text-primary/70">
                        {[user.city, user.country].filter(Boolean).join(", ") || "Unknown"}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-sm text-text-primary/70">{user.isp || "Unknown"}</span>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-sm font-medium text-text-primary">{user.session_count}</span>
                  </td>
                  <td className="px-6 py-4">
                    <ThreatBadgeLocal level={user.threat_level} />
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <Clock className="w-4 h-4 text-text-muted" />
                      <span className="text-sm text-text-muted">
                        {user.last_seen ? formatDateTime(user.last_seen) : "N/A"}
                      </span>
                    </div>
                  </td>
                </tr>
              ))}
              {vpnUsers?.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-text-muted">
                    No VPN users detected in the last 24 hours
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </motion.div>
    </motion.div>
  );
}
