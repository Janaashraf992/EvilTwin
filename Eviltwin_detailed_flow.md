

```
                   ATTACKER CONNECTS — SSH to Gateway Port 22
═══════════════════════════════════════════════════════════════════════════

  STEP 1: TCP connection accepted by asyncssh
          SSH encryption handshake begins (invisible to user)

  STEP 2: SSH handshake completes → 4 signals captured
          ┌─────────────────────────────────────────┐
          │ src_ip:           185.220.101.34         │
          │ src_port:         45122                  │
          │ client_version:   "OpenSSH_8.4p1"        │
          │ kex_algs_hash:    "a3f2b9c10d4e"        │
          │ _connect_time:    14:35:01.000           │
          └─────────────────────────────────────────┘

  STEP 3: Auth begins — username typed (no new signals yet)
          Gateway says "prove who you are"

  STEP 4: Password/key attempts → 9 more signals captured
          ┌─────────────────────────────────────────────────────┐
          │ time_to_first_auth:   0.850s (first auth - connect)│
          │ auth_attempts_count:  e.g. 5                       │
          │ auth_methods_used:    ["password"]                  │
          │ usernames_tried:      ["root", "admin"]             │
          │ passwords_tried:      ["admin123", "password", ...] │
          │ public_key_attempted: false                         │
          │ auth_attempt_interval: 0.250s                       │
          │ shell_requested:      false                         │
          │ exec_command:         null                          │
          │ is_interactive:       false                         │
          └─────────────────────────────────────────────────────┘

  STEP 5: Gateway fires POST /score/initial?attempt=1
          (fires on FIRST auth attempt, 13 signals in payload)
          Backend receives → starts classify_connection()
```

```
═══════════════════════════════════════════════════════════════════════════
                      BACKEND: classify_connection()
═══════════════════════════════════════════════════════════════════════════

  ┌─────────────────────────────────────────────────────────────────────┐
  │  DATABASE OPERATIONS (before any decision)                         │
  │                                                                     │
  │  1. Cleanup: DELETE stale gateway sessions >5min old for this IP   │
  │  2. R12 check: SELECT ANY sessions from this IP within 60s          │
  │     → is_reconnect = True/False                                    │
  │  3. Subnet scan: COUNT DISTINCT IPs in same /24 within 60s          │
  │     → subnet_ip_count = N                                          │
  │  4. Find gateway session to reuse (re-call detection)              │
  │  5. Get/Create AttackerProfile (upsert)                            │
  │     → profile.threat_level, profile.total_sessions                 │
  │  6. Create SessionLog (or reuse from pass 1)                       │
  │     → session_id = UUID, session.attacker = profile                │
  └─────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────┐
  │  PRE-GATE (skip all tiers for known attackers)                     │
  │                                                                     │
  │  IF profile.threat_level ≥ 2  AND  profile.total_sessions ≥ 1:     │
  │      → "honeypot"  confidence=1.00  [ROUTE NOW — zero overhead]    │
  │  ELSE: continue to tiers below                                      │
  └─────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────┐
  │  TIER 1: 18 HEURISTIC RULES (first-match-wins)                     │
  │                                                                     │
  │  R1  Whitelist CIDR          → real       1.00                     │
  │  R2  Pentester CIDR          → honeypot   0.95                     │
  │  R3  Known Scanner IP Range  → honeypot   0.98                     │
  │  R4  Deprecated SSH Client   → honeypot   0.95                     │
  │  R5  Pubkey + Clean Username → real       0.92                     │
  │  R6  Pubkey + Suspicious +   → honeypot   0.88  (FIXED: needs bot) │
  │      Bot Signal (<0.5s or reconnect)                               │
  │  R7  Credential Spray (≥4)   → honeypot   0.97                     │
  │  R8  Username Enum (≥3)      → honeypot   0.92                     │
  │  R9  Suspicious User + Bot   → honeypot   0.88                     │
  │  R10 Bot Auth Speed (<0.3s)  → honeypot   0.90                     │
  │  R11 Bot Connect (<0.15s)    → honeypot   0.82                     │
  │  R12 Rapid Reconnect (60s)   → honeypot   0.88                     │
  │  R13 Multi-Method Auth       → honeypot   0.85                     │
  │  R14 Suspicious Exec Command → honeypot   0.95                     │
  │  R15 Clean Non-Interactive   → real       0.72                     │
  │  R16 Clean Interactive+Key   → real       0.85                     │
  │  R17 Clean Password Login    → real       0.72                     │
  │  R18 No Strong Signal        → undecided  0.50                     │
  └─────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────┐
  │  SIGNAL EXTRACTION (23 features for ML + LLM)                      │
  │                                                                     │
  │  From raw payload:                                                  │
  │    auth_attempts_count, unique_username_count,                       │
  │    suspicious_username_count, time_to_first_auth,                    │
  │    auth_attempt_interval, public_key_attempted, shell_requested,     │
  │    is_interactive, has_exec_command, suspicious_exec, safe_exec,    │
  │    is_deprecated_client, is_rapid_reconnect, auth_method_count,     │
  │    hour_of_day, is_weekend, is_known_scanner_ip, is_tor             │
  │                                                                     │
  │  Password analysis:                                                  │
  │    avg_password_entropy  (0.0=weak/common → 1.0=strong/complex)     │
  │    has_common_password   (1.0 if pw in top 25 list)                 │
  │    repeating_password    (1.0 if same pw retried → typo / legit)    │
  │    rotating_passwords    (1.0 if all different → enumeration)       │
  │                                                                     │
  │  Network context:                                                   │
  │    subnet_ip_count       (distinct IPs in /24 within 60s)           │
  └─────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────┐
  │  TIER 2: ML — VotingClassifier (LR + GradientBoost + CatBoost)     │
  │                                                                     │
  │  3 models, soft voting, weights [1, 1.5, 2]:                        │
  │    ┌─ LogisticRegression       (linear baseline, calibrated)        │
  │    ├─ GradientBoostingClassifier (tree interactions, sklearn)       │
  │    └─ CatBoostClassifier      (gradient boosting, state-of-art)    │
  │                                                                     │
  │  23 features → predict_proba → [honeypot_prob, real_prob]           │
  │  Returns: (level, confidence, "real"|"honeypot")                    │
  │  Level: 0=real, 4=honeypot                                         │
  │  Model: ai/pre_session_model.pkl  (10000 samples, 99.3% CV)        │
  └─────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────┐
  │  TIER 3: ARBITRATE — Rules vs ML comparison                        │
  │                                                                     │
  │  1. ML unavailable?        → inconclusive                           │
  │  2. Rules=undecided?       → ML decides (conf ≥ 0.75? → decided)   │
  │  3. Both AGREE?                                                      │
  │       combined conf ≥ 0.75 → "decided"  (route NOW, no LLM)         │
  │       combined conf < 0.75 → "inconclusive"                         │
  │  4. ML OVERRIDE: rule=honeypot + ML=real≥0.85 → "real" (decided)   │
  │     (bypasses R6 false-positive for admins with root+key)           │
  │  5. RULES OVERRIDE: rule=real≥0.95 → "real" (decided)              │
  │     (whitelist/high-confidence rules overrule ML disagreement)      │
  │  6. Otherwise → "inconclusive" (disagree or low confidence)         │
  └─────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────┐
  │  TIER 4: LLM — DEEPSEEK (final arbiter, only when STILL stuck)     │
  │                                                                     │
  │  Gate: IF verdict=="inconclusive" AND attempt==1:                   │
  │      → return "inconclusive" → gateway WAITS for signals            │
  │      → LLM does NOT run yet (too expensive, signals too sparse)     │
  │                                                                     │
  │  Gate: IF verdict=="inconclusive" AND attempt==2:                   │
  │      → LLM runs (2 retries, 1.5s backoff)                           │
  │      → 19-line prompt: IP, client, timing, methods, usernames,      │
  │        exec context, tor exit node, password quality, subnet activity,│
  │        rules recommendation + ML verdict + confidence                │
  │      → DeepSeek returns {"decision","confidence","explanation"}     │
  │      → If LLM fails: "honeypot" 0.55 (safe default)                │
  │                                                                     │
  │  Gate: IF verdict=="decided" (any attempt):                         │
  │      → LLM skipped entirely (zero cost)                             │
  └─────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────┐
  │  POST-DECISION DB CLEANUP                                           │
  │                                                                     │
  │  decision == "real":                                                 │
  │      IF total_sessions == 0 (brand new IP, no attack history):       │
  │           db.delete(profile) → cascade deletes session               │
  │           → ZERO trace in DB                                         │
  │      ELSE (total_sessions >= 1, has prior attack history):           │
  │           delete(SessionLog) only                                    │
  │           → Profile KEPT as threat intel reference                   │
  │                                                                     │
  │  decision == "honeypot":                                             │
  │      profile.last_seen = now                                        │
  │      profile.total_sessions += 1                                    │
  │      session KEPT in DB (honeypot log tailer enriches later)        │
  │                                                                     │
  │  decision == "inconclusive":                                         │
  │      Nothing — gateway will retry (session stays for reuse)         │
  └─────────────────────────────────────────────────────────────────────┘

  RETURN: {decision, confidence, reason, user_type, ml_level,
           ml_confidence, llm_used, llm_explanation}
```

```
═══════════════════════════════════════════════════════════════════════════
                      BACK TO GATEWAY
═══════════════════════════════════════════════════════════════════════════

  Gateway receives response from POST /score/initial?attempt=1

  ┌─ decision == "real"/"honeypot" (decided):
  │     → set_decision() → route immediately
  │
  └─ decision == "inconclusive":
        │
        ├─ Check ready (≥3 auth attempts OR shell/exec OR 5s timeout)
        │     │
        │     ├─ ready=True → skip wait, go directly to 2nd POST
        │     └─ ready=False → wait loop (0.3s polling, max 5s)
        │           → attacker types more passwords → ready becomes True
        │           → OR timeout (5s) → break
        │
        └─ POST /score/initial?attempt=2  (with richer payload)
              → backend re-runs pipeline with more signals
              → Gateway timeout: 18s (enough for DeepSeek)
              │
              ├─ "real"     → route to real server (proxy credentials)
              ├─ "honeypot" → route to Cowrie honeypot
              └─ still inconclusive → force "honeypot" 0.50 (safe default)
```

```
═══════════════════════════════════════════════════════════════════════════
                    ROUTING (after decision)
═══════════════════════════════════════════════════════════════════════════

  REAL SERVER path:
      Gateway connects to real SSH server with attacker's credentials
      → transparent proxy (bidirectional copy)

  HONEYPOT path:
      Gateway connects to Cowrie SSH honeypot with attacker's credentials
      → attacker interacts with decoy
      → Cowrie logs all commands, credentials, malware
      → Log tailer enriches the SessionLog in DB
      → POST-SESSION ML (RandomForest, 21 features) scores threat level
      → threat_level feeds pre-gate on next reconnect
```

```
═══════════════════════════════════════════════════════════════════════════
                    DECISION EXAMPLES (15 tested)
═══════════════════════════════════════════════════════════════════════════

 SCENARIO                    RULES        ML          FINAL       PATH
 ─────────────────────────────────────────────────────────────────────────
 Cred spray 5att             honeypot    honeypot      honeypot    R7 fast
 Admin root+key slow         undecided   real→1.00     real        ML decides
 Password clean slow         real        real          real        R17 fast
 Username enum 5             honeypot    honeypot      honeypot    R8 fast
 Deprecated client           honeypot    honeypot      honeypot    R4 fast
 DevOps git pull+key         real        real          real        R15 fast
 Exploit curl|bash           honeypot    honeypot      honeypot    R14 fast
 Tor privacy+key             undecided   real→1.00     real        ML decides
 Brute slow 8att             honeypot    honeypot      honeypot    R7 fast
 CI/CD deploy+key            real        honeypot      real        Rules override
 Reconnect attacker          honeypot    honeypot      honeypot    R12 fast
 Stolen key root+slow        undecided   real→1.00     real        ML decides
 Scanner known IP            honeypot    honeypot      honeypot    R3 fast
 Whitelist IP                real        honeypot      real        R1 override
 Tor bot 5att                honeypot    honeypot      honeypot    R7 fast
 ─────────────────────────────────────────────────────────────────────────
 15/15 PASSED. 12 fast-path (no LLM). 3 ML-decided (no LLM).
 ZERO LLM calls in any test scenario.
```


Here's how the computation works for the **ML Tier** (`gateway_scorer.py:421-444` and `train_pre_session.py:532-535`):

### Ensemble: `VotingClassifier` with soft voting

```
weights = [1, 1.5, 2]    # LR : GB : CatBoost
```

Each model outputs `predict_proba` → `[p_honeypot, p_real]`. The ensemble takes a **weighted average**:

```
P_real     = (1.0 * P_lr_real  +  1.5 * P_gb_real  +  2.0 * P_cb_real) / 4.5
P_honeypot = (1.0 * P_lr_honey +  1.5 * P_gb_honey +  2.0 * P_cb_honey) / 4.5
```

CatBoost has the highest weight (2), meaning it dominates the final vote.

### Mapping to (level, confidence, decision)

```python
confidence = max(p_honeypot, p_real)       # winning probability
decision   = "real"      if p_real >= 0.5  # proba[1]
           = "honeypot"  if p_honey > 0.5  # proba[0]
level      = 0 if real,  4 if honeypot     # just a binary flag
```

There's no fuzzy level — it's a binary threshold at 0.5:
- `level 0` = real user (majority ML weight says real)
- `level 4` = honeypot attacker (majority ML weight says honeypot)
- `confidence` = how sure the ensemble is about its winning prediction (e.g. 0.72 means 72% probability for the chosen class)

### In the broader flow (Tier 3 arbitration)

The level/confidence/decision feeds into `_arbitrate()` at line 451, where it's reconciled against rule-based heuristics:
- Both agree & combined ≥ 0.75 → **decided immediately**
- ML strongly says "real" (≥ 0.85) → **ML overrides weak heuristic rules**
- Rules strongly say "real" (≥ 0.95) → **rules overrule ML**
- Disagree → **inconclusive → escalates to LLM tiebreaker**







**R13 Multi-Method Auth** at `backend/services/gateway_scorer.py:354-356`:

```python
if len(payload.auth_methods_used) >= 2 and payload.auth_attempts_count >= 3:
    return ("honeypot", 0.85, ...)
```

**Rationale for "honeypot" classification:**
- Real SSH users authenticate with a **single** method (password *or* publickey *or* keyboard-interactive)
- Automated scanners/probers cycle through multiple auth methods (`none` → `password` → `keyboard-interactive` → `publickey`) to enumerate server capabilities or find a working path — this is a strong automation signal
- 3+ total attempts with 2+ different methods in a short window is characteristic of probing tools, not humans

**Why you might say "this is not real" (false positive concern):**
- SSH clients configured with `PreferredAuthentications=publickey,password` will try publickey (fail if no key loaded), then fall back to password → 2 methods, potentially 3+ attempts if passwords are mistyped
- Some CI/CD tools, deployment scripts, or SSH configs legitimately cascade through methods
- A legitimate user with an agent forwarding issue could trigger multiple method fallbacks

**However**, in this system's context (detecting attackers hitting **honeypot** servers), the rule is intentionally aggressive. The safety net is at line 502 — if **ML** says "real" with ≥ 0.85 confidence, it **overrides** the heuristic, so well-behaved legitimate traffic with multi-method auth can still be rescued by the ML model.

The question is: are you seeing this rule misclassify traffic you believe is legitimate?






















═══════════════════════════════════════════════════════════════════════════
                    ATTACKER (decision = "honeypot")
═══════════════════════════════════════════════════════════════════════════

Gateway decides "honeypot" for 10.0.1.10
    │
    ├─ set_decision("honeypot")       → SSH proxy → 10.0.2.10 (Cowrie)
    └─ POST /sdns/flows               → Ryu installs OpenFlow rules
       {"ip":"10.0.1.10",                  │
        "target":"honeypot"}               ▼
                                     ┌──────────────────────────┐
                                     │ INGRESS FLOW             │
                                     │ Match: src=10.0.1.10     │
                                     │ Action: SET dst=10.0.2.10│
                                     │ Output: port 3 (honeypot)│
                                     ├──────────────────────────┤
                                     │ EGRESS FLOW              │
                                     │ Match: src=10.0.2.10     │
                                     │        dst=10.0.1.10     │
                                     │ Action: Output port 1    │
                                     └──────────────────────────┘
                                              │
                                              ▼
                                     ALL traffic from 10.0.1.10:
                                     → HTTP → 10.0.2.10 (Dionaea)
                                     → FTP  → 10.0.2.10 (Dionaea)
                                     → SMB  → 10.0.2.10 (Dionaea)
                                     → MSSQL→ 10.0.2.10 (Dionaea)
                                     → ANY  → 10.0.2.10


═══════════════════════════════════════════════════════════════════════════
                    NORMAL USER (decision = "real")
═══════════════════════════════════════════════════════════════════════════

Gateway decides "real" for 10.0.1.20
    │
    ├─ set_decision("real")           → SSH proxy → 10.0.1.100 (dummy banner)
    └─ POST /sdns/flows               → Ryu installs OpenFlow rules
       {"ip":"10.0.1.20",                  │
        "target":"real"}                    ▼
                                     ┌──────────────────────────┐
                                     │ INGRESS FLOW             │
                                     │ Match: src=10.0.1.20     │
                                     │ Action: SET dst=10.0.1.100│
                                     │ Output: port 5 (real)     │
                                     ├──────────────────────────┤
                                     │ EGRESS FLOW              │
                                     │ Match: src=10.0.1.100    │
                                     │        dst=10.0.1.20     │
                                     │ Action: Output port 2    │
                                     └──────────────────────────┘
                                              │
                                              ▼
                                     ALL traffic from 10.0.1.20:
                                     → HTTP → 10.0.1.100 ("You are normal")
                                     → FTP  → 10.0.1.100 (real banner)
                                     → ANY  → 10.0.1.100

                                     SSH terminal shows:
                                     "Welcome to Ubuntu 22.04.2 LTS"
                                     "You are authenticated as a legitimate user"
                                     user@real-server:~$ _


═══════════════════════════════════════════════════════════════════════════
                    SIDE-BY-SIDE
═══════════════════════════════════════════════════════════════════════════

  ATTACKER 10.0.1.10                   NORMAL USER 10.0.1.20
  ─────────────────────                ────────────────────────
  SSH:    Cowrie (fake shell)          SSH:    Dummy banner (welcome msg)
  HTTP:   Dionaea traps request        HTTP:   "You are normal user" page
  FTP:    Dionaea captures creds       FTP:    Real banner / nothing
  SMB:    Dionaea decoy                SMB:    Real banner / nothing
  MSSQL:  Dionaea honey db             MSSQL:  Real banner / nothing

  ALL commands logged to DB            NOTHING logged (session deleted)
  ML scores threat level               Zero trace preserved
  Profile: total_sessions += 1         Profile: deleted (total_sessions=0)
  Next reconnect: pre-gate honeypot    Next reconnect: fresh evaluation

  SAME GATEWAY. SAME PROCESS. DIFFERENT DESTINATIONS.
  ONE OPENFLOW RULE PER IP. ATTACKER CANNOT TELL THE DIFFERENCE.
