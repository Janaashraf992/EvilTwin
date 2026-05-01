import { CommandTimeline } from "./CommandTimeline";
import { ThreatBadge } from "../shared/ThreatBadge";
import { VpnBadge } from "../shared/VpnBadge";
import type { SessionLog } from "../../types";

export function SessionDetail({ session }: { session: SessionLog | null }) {
  if (!session) {
    return (
      <div className="glass flex h-full items-center justify-center rounded-xl p-8 shadow-panel border-border/50">
        <p className="font-mono text-sm text-text-muted animate-pulse">Waiting for session selection...</p>
      </div>
    );
  }

  return (
    <section className="glass rounded-xl p-0 shadow-panel overflow-hidden flex flex-col h-full border-border/80">
      {/* Terminal Title Bar */}
      <div className="bg-[#1c2336] px-4 py-2 flex items-center gap-3 border-b border-border/50">
        <div className="flex gap-1.5">
          <div className="w-3 h-3 rounded-full bg-[#E63946]" />
          <div className="w-3 h-3 rounded-full bg-[#E9C46A]" />
          <div className="w-3 h-3 rounded-full bg-[#2EC4B6]" />
        </div>
        <span className="font-mono text-xs text-text-muted ml-2">eviltwin@soc:~/session/{session.id.split('-')[0]}</span>
      </div>

      <div className="p-5 flex flex-col flex-1 overflow-y-auto">
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <ThreatBadge level={session.threat_level} />
          <VpnBadge active={session.vpn_detected} />
          <span className="font-mono text-safe px-2 py-1 bg-safe/10 rounded-md border border-safe/20">{session.attacker_ip}</span>
        </div>
        
        <div className="grid grid-cols-2 gap-x-8 gap-y-2 mb-6 p-4 rounded-lg bg-[#0F1424] border border-border/50 text-sm">
          <div>
            <span className="text-text-muted uppercase text-xs tracking-wider">Honeypot</span>
            <p className="text-text-primary capitalize mt-0.5">{session.honeypot}</p>
          </div>
          <div>
            <span className="text-text-muted uppercase text-xs tracking-wider">Protocol</span>
            <p className="text-text-primary capitalize mt-0.5">{session.protocol}</p>
          </div>
          <div>
            <span className="text-text-muted uppercase text-xs tracking-wider">Start Time</span>
            <p className="text-text-primary mt-0.5 font-mono text-sm">{new Date(session.start_time).toLocaleString()}</p>
          </div>
          <div>
            <span className="text-text-muted uppercase text-xs tracking-wider">Threat Score</span>
            <p className="text-threat mt-0.5 font-mono text-sm">{session.threat_score.toFixed(2)} / 100</p>
          </div>
        </div>

        <div className="flex-1 rounded-lg overflow-hidden border border-[#2d3748]">
          <CommandTimeline commands={session.commands} />
        </div>
      </div>
    </section>
  );
}
