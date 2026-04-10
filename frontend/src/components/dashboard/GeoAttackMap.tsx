import { useMemo, useState, useEffect } from "react";
import DeckGL from "@deck.gl/react";
import { GeoJsonLayer, ArcLayer, ScatterplotLayer } from "@deck.gl/layers";
import { motion } from "framer-motion";
import type { SessionLog } from "../../types";

const GEO_URL = "https://d2ad6b4ur7yvpq.cloudfront.net/naturalearth-3.3.0/ne_110m_admin_0_countries.geojson";

// Honeypot hardcoded internal coordinate (e.g., central US)
const HONEYPOT_COORD: [number, number] = [-95.7129, 37.0902];

// Fallback coords
const COUNTRY_COORDS: Record<string, [number, number]> = {
  US: [-98, 39], DE: [10, 51], FR: [2, 46], GB: [-3, 55], CN: [104, 35],
  RU: [100, 60], IN: [78, 22], BR: [-51, -10], JP: [138, 36], KR: [128, 36],
  AU: [134, -25], CA: [-106, 56], TR: [35, 39], IR: [53, 32], PK: [69, 30],
  ZA: [22, -30], EG: [30, 26], NG: [8, 10], CO: [-74, 4], MX: [-102, 23]
};

function getThreatColorRgb(level: number): [number, number, number] {
  if (level >= 4) return [230, 57, 70]; // threat
  if (level === 3) return [244, 162, 97]; // warning
  if (level === 2) return [233, 196, 106]; 
  if (level === 1) return [46, 196, 182]; // safe
  return [107, 114, 128]; // text-muted
}

const INITIAL_VIEW_STATE = {
  longitude: 0,
  latitude: 20,
  zoom: 1.5,
  maxZoom: 16,
  pitch: 55,
  bearing: 0
};

export function GeoAttackMap({ sessions }: { sessions: SessionLog[] }) {
  const [time, setTime] = useState(0);

  // Animation loop for pulsing
  useEffect(() => {
    const interval = setInterval(() => {
      setTime(t => (t + 1) % 100);
    }, 50);
    return () => clearInterval(interval);
  }, []);

  const arcs = useMemo(() => {
    return sessions.slice(0, 150).map(s => {
      // Prioritize raw latitude/longitude from backend VPNService
      let coords: [number, number] = [0, 0];
      if (s.longitude !== undefined && s.latitude !== undefined && s.latitude !== 0) {
        coords = [s.longitude, s.latitude];
      } else {
        const code = (s.country || "").toUpperCase();
        coords = COUNTRY_COORDS[code] || [0, 0];
      }
      
      return {
        source: coords,
        target: HONEYPOT_COORD,
        color: getThreatColorRgb(s.threat_level),
        ip: s.attacker_ip,
        threat: s.threat_level,
        country: s.country || "Unknown",
        protocol: s.protocol || "unknown",
        score: s.threat_score || 0
      };
    }).filter(a => Math.abs(a.source[0]) > 0.1 || Math.abs(a.source[1]) > 0.1); // Exclude [0,0] ocean null island
  }, [sessions]);

  // Compute points for the Scatterplot
  const originPoints = arcs.map(a => ({
    position: a.source,
    color: a.color,
  }));

  const layers = [
    new GeoJsonLayer({
      id: "base-map",
      data: GEO_URL,
      stroked: true,
      filled: true,
      extruded: true,
      getElevation: (d: any) => {
        const name = d.properties?.ADMIN || d.properties?.name || "";
        if (name === "Antarctica") return 0;
        return 15000;
      }, 
      lineWidthMinPixels: 1,
      opacity: 0.9,
      getLineColor: [30, 41, 59, 255],
      getFillColor: [15, 20, 36, 255]
    }),
    new ArcLayer({
      id: "attack-arcs",
      data: arcs,
      getSourcePosition: (d: any) => d.source,
      getTargetPosition: (d: any) => d.target,
      getSourceColor: (d: any) => d.color,
      getTargetColor: [230, 57, 70], // Honeypot is red-targeted
      getWidth: (d: any) => (d.threat >= 3 ? 3 : 1.5),
      getHeight: 1.5,
      opacity: 0.8,
      pickable: true
    }),
    new ScatterplotLayer({
      id: "origin-nodes",
      data: originPoints,
      getPosition: (d: any) => [d.position[0], d.position[1], 60000], // Elevate above base map
      getFillColor: (d: any) => [d.color[0], d.color[1], d.color[2], Math.max(0, 150 - (time * 1.5))] as [number, number, number, number],
      getRadius: () => 150000 + (time * 10000), // Larger pulsing radius
      radiusMinPixels: 4,
      radiusMaxPixels: 35,
      stroked: false,
      pickable: false,
      parameters: { depthTest: false } // ensure points aren't submerged
    }),
    // Honeypot central node
    new ScatterplotLayer({
      id: "honeypot-node",
      data: [{ position: HONEYPOT_COORD }],
      getPosition: (d: any) => [d.position[0], d.position[1], 60000],
      getFillColor: [230, 57, 70, 140], // Translucent base
      getLineColor: [230, 57, 70, 200],
      lineWidthMinPixels: 2,
      stroked: true,
      getRadius: 300000 + (Math.sin(time / 10) * 80000), // Larger Radar pulse
      radiusMinPixels: 8,
      radiusMaxPixels: 45,
      parameters: { depthTest: false }
    })
  ];

  return (
    <motion.section 
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.6, delay: 0.3 }}
      className="glass-elevated rounded-xl p-4 shadow-panel h-[550px] flex flex-col relative overflow-hidden group"
    >
      <div className="flex justify-between items-center mb-3 z-10">
        <h3 className="font-display text-lg font-bold tracking-widest text-[#F1F5F9]">LIVE 3D INGRESS MAP</h3>
        <span className="animate-pulse flex items-center gap-2 text-xs text-threat font-mono bg-threat/10 px-2 py-1 rounded-md border border-threat/20">
          <div className="w-2 h-2 bg-threat rounded-full"></div> SENSORS ONLINE
        </span>
      </div>
      
      <div className="flex-1 relative rounded-lg border border-border/30 overflow-hidden bg-[#0A0E1A]/90 shadow-[inset_0_0_40px_rgba(0,0,0,0.4)]">
        <div className="absolute inset-0">
          <DeckGL
            initialViewState={INITIAL_VIEW_STATE}
            controller={true}
            layers={layers}
            getTooltip={({object}: any) => {
              if (!object) return null;
              return {
                html: `
                  <div style="font-family: monospace; background: rgba(10, 14, 26, 0.95); border: 1px solid rgba(230, 57, 70, 0.3); padding: 12px; border-radius: 8px; box-shadow: 0 0 20px rgba(0,0,0,0.8); backdrop-filter: blur(10px); min-width: 200px;">
                    <div style="color: #64748b; font-size: 10px; text-transform: uppercase; margin-bottom: 8px; letter-spacing: 1px;">Ingress Telemetry</div>
                    
                    <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                      <span style="color: #94a3b8; font-size: 12px;">Origin IP</span>
                      <span style="color: #f8fafc; font-weight: bold; font-size: 12px;">${object.ip}</span>
                    </div>
                    
                    <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                      <span style="color: #94a3b8; font-size: 12px;">Location</span>
                      <span style="color: #f8fafc; font-size: 12px;">${object.country} [${object.source[1].toFixed(2)}, ${object.source[0].toFixed(2)}]</span>
                    </div>

                    <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                      <span style="color: #94a3b8; font-size: 12px;">Protocol</span>
                      <span style="color: rgba(46, 196, 182, 1); font-weight: bold; text-transform: uppercase; font-size: 12px;">${object.protocol}</span>
                    </div>

                    <div style="display: flex; justify-content: space-between; margin-top: 8px; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.1);">
                      <span style="color: #94a3b8; font-size: 12px;">Threat Score</span>
                      <span style="color: ${object.threat >= 3 ? 'rgba(230, 57, 70, 1)' : 'rgba(233, 196, 106, 1)'}; font-weight: bold; font-size: 12px;">
                        ${(object.score * 100).toFixed(1)}% (Lvl ${object.threat})
                      </span>
                    </div>
                  </div>
                `,
                style: {
                  backgroundColor: 'transparent',
                  padding: '0px',
                  pointerEvents: 'none' as const
                }
              };
            }}
          />
        </div>
        {/* Futuristic Overlay Grid */}
        <div className="absolute inset-0 pointer-events-none mix-blend-overlay opacity-10" style={{ backgroundImage: 'linear-gradient(rgba(255, 255, 255, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.1) 1px, transparent 1px)', backgroundSize: '40px 40px'}}></div>
      </div>
      
      {/* Legend */}
      <div className="absolute bottom-6 left-6 space-y-2 pointer-events-none z-10 glass px-4 py-3 rounded-[10px] border border-white/10 shadow-[0_0_30px_rgba(0,0,0,0.5)]">
        <div className="flex items-center gap-3">
          <div className="w-1.5 h-1.5 rounded-full shadow-[0_0_8px_rgba(230,57,70,1)]" style={{ backgroundColor: "rgba(230,57,70,1)"}}></div>
          <span className="text-[10px] text-white/70 font-mono tracking-widest font-medium">CRITICAL INGRESS</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="w-1.5 h-1.5 rounded-full shadow-[0_0_8px_rgba(244,162,97,1)]" style={{ backgroundColor: "rgba(244,162,97,1)"}}></div>
          <span className="text-[10px] text-white/70 font-mono tracking-widest font-medium">HIGH THREAT</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="w-1.5 h-1.5 rounded-full shadow-[0_0_8px_rgba(46,196,182,1)]" style={{ backgroundColor: "rgba(46,196,182,1)"}}></div>
          <span className="text-[10px] text-white/70 font-mono tracking-widest font-medium">BASIC PROBE</span>
        </div>
      </div>
    </motion.section>
  );
}
