export interface Command {
  timestamp: string;
  command: string;
  output?: string;
}

export interface Credential {
  username: string;
  password: string;
  success: boolean;
}

export interface SessionLog {
  id: string;
  attacker_ip: string;
  honeypot: string;
  protocol: string;
  start_time: string;
  end_time: string | null;
  commands: Command[];
  credentials_tried: Credential[];
  malware_hashes: string[];
  raw_log: Record<string, unknown>;
  threat_score: number;
  threat_level: number;
  country?: string;
  city?: string;
  isp?: string;
  latitude?: number;
  longitude?: number;
  vpn_detected: boolean;
}

export interface SessionListResponse {
  items: SessionLog[];
  total: number;
  page: number;
  pages: number;
}

export interface Alert {
  id: string;
  session_id: string;
  attacker_ip: string;
  threat_level: number;
  message: string;
  created_at: string;
  acknowledged: boolean;
}

export interface DashboardStats {
  total_sessions_24h: number;
  unique_attackers_24h: number;
  critical_alerts_24h: number;
  top_commands: Array<{ command: string; count: number }>;
  attacks_by_hour: Array<{ hour: number; count: number }>;
  threat_level_distribution: Array<{ level: number; count: number }>;
}
