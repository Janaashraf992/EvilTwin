Signals arriving from Gateway (POST /score/initial)


{
  src_ip: "185.220.101.34",        src_port: 45122,
  client_version: "OpenSSH_8.4p1", kex_algorithms_hash: "a3f2b9c10d4e",
  time_to_first_auth: 0.85,        auth_attempts_count: 3,
  auth_methods_used: ["password"],  usernames_tried: ["root", "admin"],
  public_key_attempted: false,      shell_requested: false,
  exec_command: null,               is_interactive: false,
  auth_attempt_interval: 0.45
}



Tier 1: Heuristic Rules Engine (0ms, no I/O)
What it does: Stateless pattern matching. Checks signals against 9 hardcoded rules in priority order. First match wins — no further rules evaluated.
[]

                          ATTACKER CONNECTS (TCP port 22)
                                    │
                          SSH handshake complete
                          4 signals captured
                                    │
                          Auth attempt(s) collected
                          Gateway POSTs /score/initial
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     classify_connection(payload, attempt, db)           │
│                                                                         │
│  ┌─ DB: cleanup stale >5min, check reconnect, subnet scan,             │
│  │       create/update AttackerProfile + SessionLog                     │
│  │                                                                      │
│  ├─ PRE-GATE: profile.threat_level ≥ 2  AND  sessions ≥ 1 ?            │
│  │   └─ YES → "honeypot" 1.00 (immediate, skip all tiers)              │
│  │                                                                      │
│  ├─ TIER 1: 18 Heuristic Rules (first-match-wins)                       │
│  │   ├─ R1 Whitelist → real                                           │
│  │   ├─ R2-4 Pentester/Scanner/Deprecated → honeypot                  │
│  │   ├─ R5 Key+clean → real                                           │
│  │   ├─ R6 Key+suspicious+bot → honeypot    (FIXED: needs bot signal) │
│  │   ├─ R7-14 Spray/Enum/Bot/Reconnect/Exploit → honeypot             │
│  │   ├─ R15-17 Clean exec/shell/password → real                       │
│  │   └─ R18 Undecided → "undecided" 0.50                              │
│  │                                                                      │
│  ├─ TIER 2: ML VotingClassifier (LR + GB + CatBoost)                   │
│  │   └─ 23 real features → (level, confidence, decision)                │
│  │                                                                      │
│  ├─ TIER 3: Arbitrate (Rules vs ML)                                     │
│  │   ├─ Agree + conf ≥ 0.75 → "decided" (boosted conf)                 │
│  │   ├─ ML override: rule=honeypot, ML=real≥0.85 → real                │
│  │   ├─ Rules override: rule=real≥0.95 → real                          │
│  │   └─ Disagree or low conf → "inconclusive"                          │
│  │                                                                      │
│  ├─ TIER 4: LLM (attempt=2 only, 2 retries with backoff)               │
│  │   └─ 18-line prompt with full signal context → deepseek decides     │
│  │                                                                      │
│  └─ CLEANUP:                                                            │
│      ├─ "real"      → DELETE session + profile (if new)               │
│      ├─ "honeypot"  → KEEP session + update counters                   │
│      └─ "inconclusive" → leave for gateway retry                       │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                          Gateway receives decision
                          routes to real or honeypot
