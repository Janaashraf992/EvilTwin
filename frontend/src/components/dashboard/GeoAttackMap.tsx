import { useMemo, useState, useEffect } from "react";
import { DeckGL } from "@deck.gl/react";
import { GeoJsonLayer, ArcLayer, ScatterplotLayer } from "@deck.gl/layers";
import { motion } from "framer-motion";
import type { SessionLog } from "../../types";

const GEO_URL = "https://d2ad6b4ur7yvpq.cloudfront.net/naturalearth-3.3.0/ne_50m_admin_0_countries.geojson";

const HONEYPOT_COORD: [number, number] = [31.2357, 30.0444];

const COUNTRY_COORDS: Record<string, [number, number]> = {
  US: [-98, 39], DE: [10, 51], FR: [2, 46], GB: [-3, 55], CN: [104, 35],
  RU: [100, 60], IN: [78, 22], BR: [-51, -10], JP: [138, 36], KR: [128, 36],
  AU: [134, -25], CA: [-106, 56], TR: [35, 39], IR: [53, 32], PK: [69, 30],
  ZA: [22, -30], EG: [30, 26], NG: [8, 10], CO: [-74, 4], MX: [-102, 23]
};

const CONTINENT_FILLS: Record<string, [number, number, number, number]> = {
  "North America": [107, 142, 75, 255],
  "South America": [76, 135, 60, 255],
  "Europe":        [120, 155, 90, 255],
  "Africa":        [194, 178, 128, 255],
  "Asia":          [155, 160, 100, 255],
  "Oceania":       [140, 160, 90, 255],
  "Antarctica":    [210, 220, 230, 255],
};

function getContinentFillColor(props: any): [number, number, number, number] {
  const continent = props?.CONTINENT || props?.continent || "";
  return CONTINENT_FILLS[continent] || [130, 140, 100, 255];
}

function getThreatColorRgb(level: number): [number, number, number] {
  if (level >= 4) return [230, 57, 70];
  if (level === 3) return [244, 162, 97];
  if (level === 2) return [233, 196, 106];
  if (level === 1) return [46, 196, 182];
  return [107, 114, 128];
}

const INITIAL_VIEW_STATE = {
  longitude: 31,
  latitude: 28,
  zoom: 1.5,
  maxZoom: 16,
  pitch: 55,
  bearing: 0
};

export function GeoAttackMap({ sessions }: { sessions: SessionLog[] }) {
  const [geoData, setGeoData] = useState<any>(null);
  const [time, setTime] = useState(0);

  useEffect(() => {
    fetch(GEO_URL)
      .then(r => r.json())
      .then(fc => {
        for (const feat of fc.features) {
          const p = feat.properties;
          if (p.admin === "Israel" || p.name === "Israel") {
            p.admin = "Palestine";
            p.name = "Palestine";
            p.name_long = "Palestine";
            p.formal_en = "State of Palestine";
            p.name_sort = "Palestine";
            p.brk_name = "Palestine";
            p.geounit = "Palestine";
            p.sovereignt = "Palestine";
            p.subunit = "Palestine";
            p.sov_a3 = "PSE";
            p.adm0_a3 = "PSE";
            p.gu_a3 = "PSE";
            p.su_a3 = "PSE";
            p.brk_a3 = "PSE";
          }
        }
        setGeoData(fc);
      })
      .catch(() => { /* CDN unreachable — map renders without geography */ });
  }, []);

  useEffect(() => {
    const interval = setInterval(() => {
      setTime(t => (t + 1) % 100);
    }, 50);
    return () => clearInterval(interval);
  }, []);

  const arcs = useMemo(() => {
    return sessions.slice(0, 150).map(s => {
      let coords: [number, number] = HONEYPOT_COORD;
      if (s.longitude != null && s.latitude != null && (s.latitude !== 0 || s.longitude !== 0)) {
        coords = [s.longitude, s.latitude];
      } else {
        const code = (s.country || "").toUpperCase();
        if (code && COUNTRY_COORDS[code]) {
          coords = COUNTRY_COORDS[code];
        }
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
    }).filter(a => Math.abs(a.source[0]) > 0.1 || Math.abs(a.source[1]) > 0.1);
  }, [sessions]);

  const attackedCountries = useMemo(() => {
    const map = new Map<string, { color: [number, number, number]; maxThreat: number }>();
    for (const arc of arcs) {
      const name = arc.country;
      const existing = map.get(name);
      if (!existing || arc.threat > existing.maxThreat) {
        map.set(name, { color: arc.color, maxThreat: arc.threat });
      }
    }
    return map;
  }, [arcs]);

  const glowAlpha = 140 + Math.floor(Math.abs(Math.sin(time / 8)) * 115);

  const layers = [
    geoData && new GeoJsonLayer({
      id: "land-fill",
      data: geoData,
      stroked: false,
      filled: true,
      extruded: false,
      getFillColor: (d: any) => getContinentFillColor(d.properties),
      pickable: true,
    }),

    geoData && new GeoJsonLayer({
      id: "country-borders",
      data: geoData,
      stroked: true,
      filled: false,
      extruded: false,
      getLineColor: (d: any) => {
        const name = d.properties?.ADMIN || d.properties?.name || "";
        const entry = attackedCountries.get(name);
        if (entry) {
          return [...entry.color, 200] as [number, number, number, number];
        }
        return [40, 55, 75, 120] as [number, number, number, number];
      },
      lineWidthMinPixels: 0.5,
      lineWidthMaxPixels: 1.5,
      pickable: false,
    }),

    geoData && new GeoJsonLayer({
      id: "country-glow",
      data: geoData,
      stroked: true,
      filled: false,
      extruded: false,
      getLineColor: (d: any) => {
        const name = d.properties?.ADMIN || d.properties?.name || "";
        const entry = attackedCountries.get(name);
        if (entry) {
          return [...entry.color, glowAlpha] as [number, number, number, number];
        }
        return [0, 0, 0, 0] as [number, number, number, number];
      },
      lineWidthMinPixels: 2.5,
      lineWidthMaxPixels: 5,
      pickable: false,
    }),

    new ArcLayer({
      id: "attack-arcs",
      data: arcs,
      getSourcePosition: (d: any) => d.source,
      getTargetPosition: (d: any) => d.target,
      getSourceColor: (d: any) => d.color,
      getTargetColor: (d: any) => d.color,
      getWidth: (d: any) => (d.threat >= 3 ? 3 : 1.5),
      getHeight: 1.5,
      opacity: 0.8,
      pickable: true,
    }),

    new ScatterplotLayer({
      id: "honeypot-node",
      data: [{ position: HONEYPOT_COORD }],
      getPosition: (d: any) => [d.position[0], d.position[1], 59000],
      getFillColor: [0, 0, 0, 0],
      getLineColor: [200, 200, 200, 100],
      lineWidthMinPixels: 1,
      stroked: true,
      filled: false,
      getRadius: 120000,
      radiusMinPixels: 4,
      radiusMaxPixels: 12,
      parameters: { depthTest: false },
    }),

    new ScatterplotLayer({
      id: "origin-nodes",
      data: arcs,
      getPosition: (d: any) => [d.source[0], d.source[1], 61000],
      getFillColor: (d: any) => [...d.color, 200] as [number, number, number, number],
      getRadius: 200000 + Math.sin(time / 8) * 60000,
      radiusMinPixels: 6,
      radiusMaxPixels: 40,
      stroked: true,
      getLineColor: (d: any) => [...d.color, 255] as [number, number, number, number],
      lineWidthMinPixels: 2,
      pickable: false,
      parameters: { depthTest: false },
    }),
  ].filter(Boolean);

  return (
    <motion.section
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.6, delay: 0.3 }}
      className="glass-elevated rounded-xl p-4 shadow-panel h-[550px] flex flex-col relative overflow-hidden group"
    >
      <div className="flex justify-between items-center mb-3 z-10">
        <h3 className="font-display text-lg font-bold tracking-widest text-text-primary">LIVE 3D INGRESS MAP</h3>
        <span className="animate-pulse flex items-center gap-2 text-xs text-threat font-mono bg-threat/10 px-2 py-1 rounded-md border border-threat/20">
          <div className="w-2 h-2 bg-threat rounded-full"></div> SENSORS ONLINE
        </span>
      </div>

      <div className="flex-1 relative rounded-lg border border-border/30 overflow-hidden shadow-[inset_0_0_40px_rgba(0,0,0,0.4)]" style={{ backgroundColor: "var(--color-map-ocean)" }}>
        <div className="absolute inset-0">
          <DeckGL
            initialViewState={INITIAL_VIEW_STATE}
            controller={true}
            layers={layers}
            getTooltip={({ object }: any) => {
              if (!object) return null;
              const props = object.properties || {};
              const name = props.ADMIN || props.name;
              if (name && !object.ip) {
                return {
                  html: `
                    <div style="font-family: monospace; background: var(--color-map-tooltip-bg); border: 1px solid var(--color-map-tooltip-border); padding: 10px 14px; border-radius: 8px; box-shadow: 0 0 20px rgba(0,0,0,0.8); backdrop-filter: blur(10px);">
                      <div style="color: var(--color-map-tooltip-heading); font-size: 12px; font-weight: bold;">${name}</div>
                      <div style="color: var(--color-map-tooltip-dim); font-size: 10px; margin-top: 2px;">${props.CONTINENT || ""}</div>
                    </div>
                  `,
                  style: {
                    backgroundColor: "transparent",
                    padding: "0px",
                    pointerEvents: "none" as const,
                  },
                };
              }
              return {
                html: `
                  <div style="font-family: monospace; background: var(--color-map-tooltip-bg); border: 1px solid rgba(230, 57, 70, 0.3); padding: 12px; border-radius: 8px; box-shadow: 0 0 20px rgba(0,0,0,0.8); backdrop-filter: blur(10px); min-width: 200px;">
                    <div style="color: var(--color-map-tooltip-dim); font-size: 10px; text-transform: uppercase; margin-bottom: 8px; letter-spacing: 1px;">Ingress Telemetry</div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                      <span style="color: var(--color-map-tooltip-muted); font-size: 12px;">Origin IP</span>
                      <span style="color: var(--color-map-tooltip-text); font-weight: bold; font-size: 12px;">${object.ip}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                      <span style="color: var(--color-map-tooltip-muted); font-size: 12px;">Location</span>
                      <span style="color: var(--color-map-tooltip-text); font-size: 12px;">${object.country} [${object.source[1].toFixed(2)}, ${object.source[0].toFixed(2)}]</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                      <span style="color: var(--color-map-tooltip-muted); font-size: 12px;">Protocol</span>
                      <span style="color: rgba(46, 196, 182, 1); font-weight: bold; text-transform: uppercase; font-size: 12px;">${object.protocol}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--color-map-tooltip-border);">
                      <span style="color: var(--color-map-tooltip-muted); font-size: 12px;">Threat Score</span>
                      <span style="color: ${object.threat >= 3 ? "rgba(230, 57, 70, 1)" : "rgba(233, 196, 106, 1)"}; font-weight: bold; font-size: 12px;">
                        ${(object.score * 100).toFixed(1)}% (Lvl ${object.threat})
                      </span>
                    </div>
                  </div>
                `,
                style: {
                  backgroundColor: "transparent",
                  padding: "0px",
                  pointerEvents: "none" as const,
                },
              };
            }}
          />
        </div>
        <div className="absolute inset-0 pointer-events-none mix-blend-overlay opacity-10" style={{ backgroundImage: "linear-gradient(rgba(255, 255, 255, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.1) 1px, transparent 1px)", backgroundSize: "40px 40px" }}></div>
      </div>

      <div className="absolute bottom-6 left-6 space-y-2 pointer-events-none z-10 glass px-4 py-3 rounded-[10px] border border-border shadow-[0_0_30px_rgba(0,0,0,0.5)]">
        <div className="flex items-center gap-3">
          <div className="w-1.5 h-1.5 rounded-full shadow-[0_0_8px_rgba(230,57,70,1)]" style={{ backgroundColor: "rgba(230,57,70,1)" }}></div>
          <span className="text-[10px] text-text-muted font-mono tracking-widest font-medium">LVL 4 · CRITICAL</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="w-1.5 h-1.5 rounded-full shadow-[0_0_8px_rgba(244,162,97,1)]" style={{ backgroundColor: "rgba(244,162,97,1)" }}></div>
          <span className="text-[10px] text-text-muted font-mono tracking-widest font-medium">LVL 3 · HIGH</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="w-1.5 h-1.5 rounded-full shadow-[0_0_8px_rgba(233,196,106,1)]" style={{ backgroundColor: "rgba(233,196,106,1)" }}></div>
          <span className="text-[10px] text-text-muted font-mono tracking-widest font-medium">LVL 2 · MODERATE</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="w-1.5 h-1.5 rounded-full shadow-[0_0_8px_rgba(46,196,182,1)]" style={{ backgroundColor: "rgba(46,196,182,1)" }}></div>
          <span className="text-[10px] text-text-muted font-mono tracking-widest font-medium">LVL 1 · EASY</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="w-1.5 h-1.5 rounded-full shadow-[0_0_8px_rgba(107,114,128,1)]" style={{ backgroundColor: "rgba(107,114,128,1)" }}></div>
          <span className="text-[10px] text-text-muted font-mono tracking-widest font-medium">LVL 0 · BENIGN</span>
        </div>
      </div>
    </motion.section>
  );
}
