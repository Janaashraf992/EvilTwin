import type { Command } from "../../types";

const DANGEROUS_KEYWORDS = ["wget", "curl", "chmod", "nc", "bash", "base64", "crontab", "rm"];

function isDangerous(cmdStr: string): boolean {
  return DANGEROUS_KEYWORDS.some((kw) => cmdStr.includes(kw));
}

export function CommandTimeline({ commands }: { commands: Command[] }) {
  if (commands.length === 0) {
    return (
      <div className="h-full flex items-center justify-center p-6 bg-[#0A0E1A]">
        <p className="font-mono text-sm text-text-muted italic">No interactive commands recorded.</p>
      </div>
    );
  }

  return (
    <div className="h-full bg-[#0A0E1A] overflow-y-auto font-mono text-sm p-4 space-y-3">
      {commands.map((cmd, idx) => {
        const dangerous = isDangerous(cmd.command);
        return (
          <div key={`${cmd.timestamp}-${idx}`} className="group hover:bg-[#141928] p-1.5 -mx-1.5 rounded transition-colors">
            <div className="flex items-center text-xs text-text-muted mb-1 opacity-60 group-hover:opacity-100 transition-opacity">
              <span>{new Date(cmd.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' })}</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-safe select-none mt-0.5">$</span>
              <p className={`break-all ${dangerous ? "text-threat font-semibold" : "text-text-primary"}`}>
                {cmd.command}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
}
