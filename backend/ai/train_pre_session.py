from __future__ import annotations

"""
Train a pre-session VotingClassifier (LR + GradientBoost + CatBoost)
for gateway routing decisions.

Covers 18 attacker profiles and 9 real-user profiles
across 18 features available at SSH connection time.
"""
import os
import numpy as np
import joblib

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import VotingClassifier, GradientBoostingClassifier
from catboost import CatBoostClassifier
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import classification_report, roc_auc_score

N_SAMPLES = 10000
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "pre_session_model.pkl")


def _f(val): return float(val)


def generate_synthetic_data(n_samples: int = N_SAMPLES):
    rng = np.random.RandomState(42)
    half = n_samples // 2

    X = []
    y = []

    def add(feats, label):
        data = [_f(v) for v in feats]
        has_key = feats[5] > 0  # public_key_attempted at index 5
        # Auto-generate password features based on label + whether key was used
        if has_key:
            data.append(0.0)      # avg_password_entropy (no passwords)
            data.append(0.0)      # has_common_password
            data.append(0.0)      # repeating_password
            data.append(0.0)      # rotating_passwords
        elif label == 0:  # attacker, password-based
            data.append(round(rng.uniform(0.01, 0.25), 3))
            data.append(_f(rng.choice([1, 1, 1, 0])))
            data.append(_f(rng.choice([0, 0, 0, 0, 1])))
            data.append(_f(rng.choice([1, 1, 1, 0])))
        else:  # real user, password-based
            data.append(round(rng.uniform(0.35, 0.95), 3))
            data.append(_f(rng.choice([0, 0, 0, 1])))
            data.append(_f(rng.choice([0, 0, 1, 1])))
            data.append(_f(rng.choice([0, 0, 0, 0, 1])))
        # Subnet scan: 80% normal, 20% distributed
        is_subnet_scan = rng.rand() < (0.4 if label == 0 else 0.05)
        subnet = round(rng.uniform(3, 40)) if is_subnet_scan else round(rng.uniform(0, 2))
        data.append(subnet)
        X.append(data)
        y.append(label)

    def add_n(profile, label, n):
        for _ in range(n):
            feats = profile(rng)
            add(feats, label)

    # ============================================================
    # ATTACKER PROFILES (18 types) — label=0
    # ============================================================

    def attacker_cred_spray(rng):
        """Bot spraying many passwords fast."""
        attempts = int(rng.choice([4, 5, 6, 8, 10, 12, 15, 20]))
        usernames = min(attempts, int(rng.choice([1, 1, 2, 2, 3, 4])))
        return [
            attempts,                                 # auth_attempts_count
            usernames,                                 # unique_username_count
            min(usernames, int(rng.uniform(1, usernames + 1))),  # suspicious_username_count
            round(rng.uniform(0.02, 0.40), 3),         # time_to_first_auth
            round(rng.uniform(0.03, 0.25), 3),         # auth_attempt_interval
            _f(0),                                      # public_key_attempted
            _f(rng.choice([0, 0, 0, 0, 1])),           # shell_requested
            _f(rng.choice([0, 0, 0, 1])),              # is_interactive
            _f(0),                                      # has_exec_command
            _f(0),                                      # suspicious_exec
            _f(0),                                      # safe_exec
            _f(rng.choice([0, 0, 0, 0, 1])),           # is_deprecated_client
            _f(rng.choice([0, 0, 0, 1, 1])),           # is_rapid_reconnect
            _f(min(3, attempts)),                       # auth_method_count
            float(rng.uniform(0, 24)),                 # hour_of_day
            _f(rng.choice([0, 0, 1, 1])),             # is_weekend
            _f(0),                                      # is_known_scanner_ip
            _f(rng.choice([0, 0, 0, 0, 0, 1])),        # is_tor
        ]

    def attacker_scanner(rng):
        """Port scanner: fast connect, single auth, suspicious username, known IP."""
        return [
            1,                                          # auth_attempts_count
            1,                                          # unique_username_count
            1,                                          # suspicious_username_count
            round(rng.uniform(0.01, 0.15), 3),          # time_to_first_auth
            0.0,                                        # auth_attempt_interval
            _f(0),                                      # public_key_attempted
            _f(0),                                      # shell_requested
            _f(0),                                      # is_interactive
            _f(0),                                      # has_exec_command
            _f(0),                                      # suspicious_exec
            _f(0),                                      # safe_exec
            _f(rng.choice([0, 0, 0, 0, 1])),           # is_deprecated_client
            _f(0),                                      # is_rapid_reconnect
            _f(1),                                      # auth_method_count
            float(rng.choice([0, 1, 2, 3, 4, 5, 22, 23])),  # odd hours
            _f(rng.choice([0, 1, 1, 1])),              # is_weekend
            _f(1),                                      # is_known_scanner_ip
            _f(0),                                      # is_tor
        ]

    def attacker_brute_slow(rng):
        """Stealth brute-force: many attempts at human-like speed."""
        attempts = int(rng.choice([5, 6, 7, 8, 10, 12]))
        return [
            attempts,
            int(rng.choice([1, 1, 1, 2])),            # mostly single target
            int(rng.choice([1, 1, 1, 2])),            # usually suspicious
            round(rng.uniform(0.3, 2.0), 3),           # human-like connect
            round(rng.uniform(0.5, 3.0), 3),           # human-like interval
            _f(0),
            _f(rng.choice([0, 0, 0, 1])),
            _f(rng.choice([0, 0, 1])),
            _f(0), _f(0), _f(0),
            _f(rng.choice([0, 0, 0, 0, 1])),
            _f(rng.choice([0, 0, 0, 1, 1])),          # reconnect yes
            _f(1),
            float(rng.choice([0, 1, 2, 3, 4, 22, 23])),
            _f(rng.choice([0, 0, 1, 1])),
            _f(0),
            _f(rng.choice([0, 0, 0, 1])),
        ]

    def attacker_username_enum(rng):
        """Username enumeration: many usernames, few attempts each."""
        usernames = int(rng.choice([3, 4, 5, 6, 8]))
        return [
            int(rng.choice([usernames, usernames + 2, usernames * 2])),  # attempts
            usernames,
            usernames,                                 # ALL suspicious (system usernames)
            round(rng.uniform(0.05, 0.50), 3),
            round(rng.uniform(0.05, 0.40), 3),
            _f(0),
            _f(0), _f(0), _f(0),
            _f(rng.choice([0, 0, 0, 0, 1])),
            _f(0),
            _f(rng.choice([0, 0, 0, 1])),
            _f(rng.choice([0, 0, 0, 1, 1])),
            _f(min(3, usernames)),
            float(rng.uniform(0, 24)),
            _f(rng.choice([0, 1])),
            _f(0),
            _f(0),
        ]

    def attacker_exploit(rng):
        """Exploit payload via exec command."""
        return [
            int(rng.choice([1, 1, 2])),
            1, 1,                                       # single suspicious username
            round(rng.uniform(0.1, 1.0), 3),
            round(rng.uniform(0.1, 2.0), 3),
            _f(rng.choice([0, 0, 0, 1])),              # might try key
            _f(0),
            _f(0),
            _f(1),                                      # has exec_command
            _f(1),                                      # suspicious exec
            _f(0),                                      # not safe
            _f(rng.choice([0, 0, 0, 0, 1])),
            _f(rng.choice([0, 0, 0, 1])),
            _f(1),
            float(rng.choice([0, 1, 2, 3, 4, 22, 23])),
            _f(rng.choice([0, 0, 1, 1])),
            _f(0),
            _f(rng.choice([0, 0, 0, 0, 1])),
        ]

    def attacker_tor_bot(rng):
        """Attacker coming through Tor."""
        attempts = int(rng.choice([3, 4, 5, 6, 8, 10]))
        return [
            attempts, int(rng.choice([1, 2])), int(rng.choice([1, 2])),
            round(rng.uniform(0.05, 0.50), 3),
            round(rng.uniform(0.05, 0.30), 3),
            _f(0),
            _f(rng.choice([0, 0, 0, 1])), _f(rng.choice([0, 0, 1])),
            _f(0), _f(0), _f(0),
            _f(rng.choice([0, 0, 0, 1])),
            _f(rng.choice([0, 0, 0, 1])),
            _f(min(2, attempts)),
            float(rng.uniform(0, 24)),
            _f(rng.choice([0, 1])),
            _f(rng.choice([0, 1])),                     # might be known scanner too
            _f(1),                                      # IS tor
        ]

    def attacker_reconnect(rng):
        """Reconnecting attacker within 60s."""
        return [
            int(rng.choice([1, 1, 2, 3])), 1, 1,
            round(rng.uniform(0.02, 0.30), 3),
            round(rng.uniform(0.05, 0.50), 3),
            _f(0), _f(0), _f(0), _f(0), _f(0), _f(0),
            _f(rng.choice([0, 0, 0, 1])),
            _f(1),                                      # rapid reconnect YES
            _f(1),
            float(rng.choice([0, 1, 2, 3, 4, 22, 23])),
            _f(rng.choice([0, 0, 1, 1])),
            _f(rng.choice([0, 0, 1])),
            _f(0),
        ]

    def attacker_multi_method(rng):
        """Attacker trying multiple auth methods."""
        attempts = int(rng.choice([3, 4, 5, 6, 8]))
        return [
            attempts, int(rng.choice([1, 2, 3])), int(rng.choice([1, 2, 3])),
            round(rng.uniform(0.1, 1.0), 3),
            round(rng.uniform(0.1, 2.0), 3),
            _f(rng.choice([1, 1, 1, 0])),              # often tries key first
            _f(rng.choice([0, 0, 1])),
            _f(rng.choice([0, 1])),
            _f(0), _f(0), _f(0),
            _f(rng.choice([0, 0, 0, 1])),
            _f(rng.choice([0, 0, 1, 1])),
            _f(min(3, int(rng.choice([2, 3])))),       # multi-method!
            float(rng.uniform(0, 24)),
            _f(rng.choice([0, 1])),
            _f(0),
            _f(0),
        ]

    def attacker_deprecated_client(rng):
        """Attacker using old SSH client / attack tool — always clearly malicious."""
        attempts = int(rng.choice([2, 3, 4, 5, 6]))
        return [
            attempts,
            int(rng.choice([1, 1, 1, 2])),             # mostly 1-2 usernames
            1,                                           # always suspicious
            round(rng.uniform(0.02, 0.30), 3),          # fast connect
            round(rng.uniform(0.03, 0.40), 3),          # fast interval
            _f(rng.choice([0, 0, 0, 1])),               # rarely has key
            _f(0), _f(0), _f(0),
            _f(rng.choice([0, 0, 0, 0, 1])),
            _f(0),
            _f(1),                                       # deprecated client YES
            _f(rng.choice([0, 0, 1, 1])),               # often reconnects
            _f(min(2, attempts)),
            float(rng.choice([0, 1, 2, 3, 4, 22, 23])), # odd/off hours
            _f(rng.choice([0, 0, 1, 1])),
            _f(rng.choice([0, 0, 0, 1])),
            _f(rng.choice([0, 0, 0, 1])),
        ]

    # ============================================================
    # REAL USER PROFILES (12 types) — label=1
    # ============================================================

    def real_admin_key(rng):
        """System admin: root with SSH key, interactive shell, human timing."""
        return [
            int(rng.choice([1, 1, 1, 2])),             # 1-2 attempts
            1,                                          # single username
            1 if rng.rand() < 0.7 else 0,               # root is suspicious, but with key it's legit
            round(rng.uniform(0.8, 15.0), 3),
            0.0 if rng.rand() < 0.5 else round(rng.uniform(0.5, 8.0), 3),
            _f(1),                                      # KEY
            _f(1),                                      # shell
            _f(1),                                      # interactive
            _f(rng.choice([0, 0, 0, 0, 1])),           # rarely exec
            _f(0),                                      # no suspicious exec
            _f(1 if rng.rand() < 0.1 else 0),           # rare safe exec
            _f(0),                                      # not deprecated
            _f(rng.choice([0, 0, 0, 0, 1])),           # rare reconnect
            _f(1),                                      # single method
            float(rng.choice([7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18])),  # business hours
            _f(rng.choice([0, 0, 0, 1])),
            _f(0),
            _f(0),
        ]

    def real_password_user(rng):
        """Password-only user: clean username, human timing, interactive."""
        return [
            int(rng.choice([1, 1, 1, 2])),
            1,
            0,                                          # clean username
            round(rng.uniform(1.0, 12.0), 3),
            0.0 if rng.rand() < 0.6 else round(rng.uniform(1.0, 10.0), 3),
            _f(0),                                      # NO key
            _f(rng.choice([1, 1, 1, 0])),              # mostly shell
            _f(rng.choice([1, 1, 1, 0])),
            _f(0),
            _f(0),
            _f(0),
            _f(0),
            _f(rng.choice([0, 0, 0, 0, 1])),
            _f(1),
            float(rng.choice([8, 9, 10, 11, 13, 14, 15, 16, 17])),
            _f(rng.choice([0, 0, 0, 1])),
            _f(0),
            _f(0),
        ]

    def real_devops_exec(rng):
        """DevOps: exec clean commands with key."""
        return [
            int(rng.choice([1, 1, 1, 2])),
            1, 0,
            round(rng.uniform(0.5, 8.0), 3),
            round(rng.uniform(0.5, 5.0), 3),
            _f(rng.choice([1, 1, 1, 0])),              # usually key
            _f(0),
            _f(0),
            _f(1),                                      # exec
            _f(0),                                      # NOT suspicious
            _f(1),                                      # safe exec
            _f(0),
            _f(rng.choice([0, 0, 0, 0, 1])),
            _f(1),
            float(rng.choice([6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20])),
            _f(rng.choice([0, 0, 0, 1])),
            _f(0),
            _f(0),
        ]

    def real_tor_privacy(rng):
        """Legitimate privacy user via Tor: clean behavior, key, human timing."""
        return [
            int(rng.choice([1, 1, 1, 2])),
            1,
            rng.choice([0, 0, 0, 1, 1]),               # could be ubuntu (popular on Tor)
            round(rng.uniform(1.0, 12.0), 3),
            round(rng.uniform(0.5, 10.0), 3),
            _f(rng.choice([1, 1, 1, 0])),              # usually has key
            _f(rng.choice([1, 1, 1, 0])),
            _f(rng.choice([1, 1, 1, 0])),
            _f(0),
            _f(0),
            _f(0),
            _f(0),
            _f(rng.choice([0, 0, 0, 0, 1])),
            _f(1),
            float(rng.choice([8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21, 22, 23])),
            _f(rng.choice([0, 0, 0, 1])),
            _f(0),
            _f(1),                                      # IS tor (privacy, not attack)
        ]

    def real_weekend_worker(rng):
        """Weekend worker: human timing, clean or ubuntu."""
        return [
            int(rng.choice([1, 1, 1, 2])),
            1,
            rng.choice([0, 0, 0, 1]),
            round(rng.uniform(0.8, 10.0), 3),
            round(rng.uniform(0.5, 8.0), 3),
            _f(rng.choice([1, 1, 0, 0])),
            _f(1),
            _f(1),
            _f(rng.choice([0, 0, 1])),
            _f(0),
            _f(1 if rng.rand() < 0.2 else 0),
            _f(0),
            _f(0),
            _f(1),
            float(rng.choice([9, 10, 11, 12, 13, 14, 15, 16])),
            _f(1),                                      # IS weekend
            _f(0),
            _f(0),
        ]

    def real_password_manager(rng):
        """Password manager: fast typing but clean user, single attempt, key."""
        return [
            int(rng.choice([1, 1, 1, 2])),
            1, 0,
            round(rng.uniform(0.3, 3.0), 3),
            round(rng.uniform(0.15, 0.5), 3),           # fast! but could be password manager
            _f(rng.choice([1, 1, 1, 0])),
            _f(rng.choice([1, 1, 1, 0])),
            _f(rng.choice([1, 1, 1, 0])),
            _f(0),
            _f(0),
            _f(0),
            _f(0),
            _f(rng.choice([0, 0, 0, 0, 1])),
            _f(1),
            float(rng.choice([8, 9, 10, 11, 13, 14, 15, 16, 17])),
            _f(rng.choice([0, 0, 0, 1])),
            _f(0),
            _f(0),
        ]

    def real_vpn_user(rng):
        """Legit user via VPN: similar to Tor privacy but with more corporate timing."""
        return [
            int(rng.choice([1, 1, 1, 2])),
            1,
            rng.choice([0, 0, 0, 0, 1]),
            round(rng.uniform(0.8, 8.0), 3),
            round(rng.uniform(0.5, 8.0), 3),
            _f(rng.choice([1, 1, 1, 0])),
            _f(rng.choice([1, 1, 0])),
            _f(rng.choice([1, 1, 0])),
            _f(rng.choice([0, 0, 1])),
            _f(0),
            _f(1 if rng.rand() < 0.2 else 0),
            _f(0),
            _f(0),
            _f(1),
            float(rng.choice([8, 9, 10, 11, 13, 14, 15, 16, 17])),
            _f(rng.choice([0, 0, 0, 1])),
            _f(0),
            _f(rng.choice([0, 0, 1, 1])),              # VPN detected
        ]

    def real_ci_cd(rng):
        """CI/CD pipeline: exec with key, non-interactive, predictable timing."""
        return [
            int(rng.choice([1, 1, 1, 1, 2])),
            1, 0,
            round(rng.uniform(0.1, 3.0), 3),
            round(rng.uniform(0.1, 1.0), 3),
            _f(1),                                      # always has key
            _f(0),                                      # non-interactive
            _f(0),                                      # non-interactive
            _f(1),                                      # exec
            _f(0),                                      # NOT suspicious
            _f(1),                                      # safe exec
            _f(0),
            _f(rng.choice([0, 0, 0, 0, 1])),
            _f(1),
            float(rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23])),
            _f(rng.choice([0, 0, 1, 1])),              # CI/CD runs 24/7
            _f(0),
            _f(0),
        ]

    def real_support_staff(rng):
        """Support person: might use 'admin'/'root', but with key, human timing."""
        return [
            int(rng.choice([1, 1, 1, 2])),
            1,
            1,                                          # using 'admin' — but legitimate!
            round(rng.uniform(0.8, 10.0), 3),
            round(rng.uniform(0.5, 8.0), 3),
            _f(rng.choice([1, 1, 1, 0])),
            _f(1),
            _f(1),
            _f(0),
            _f(0),
            _f(0),
            _f(0),
            _f(rng.choice([0, 0, 0, 0, 1])),
            _f(1),
            float(rng.choice([8, 9, 10, 11, 13, 14, 15, 16, 17])),
            _f(rng.choice([0, 0, 0, 1])),
            _f(0),
            _f(0),
        ]

    # ---- DISTRIBUTION: attackers (5000 samples across 9 profiles) ----
    profile_counts_attacker = [
        (attacker_cred_spray,       1200),
        (attacker_scanner,           800),
        (attacker_brute_slow,        600),
        (attacker_username_enum,     600),
        (attacker_exploit,           300),
        (attacker_tor_bot,           400),
        (attacker_reconnect,         400),
        (attacker_multi_method,      400),
        (attacker_deprecated_client, 300),
    ]
    for profile, count in profile_counts_attacker:
        add_n(profile, 0, count)

    # ---- DISTRIBUTION: real users (5000 samples across 12 profiles) ----
    profile_counts_real = [
        (real_admin_key,          700),
        (real_password_user,      700),
        (real_devops_exec,        600),
        (real_tor_privacy,        400),
        (real_weekend_worker,     400),
        (real_password_manager,   400),
        (real_vpn_user,           400),
        (real_ci_cd,              400),
        (real_support_staff,      400),
    ]
    for profile, count in profile_counts_real:
        add_n(profile, 1, count)

    return np.array(X, dtype=np.float64), np.array(y, dtype=np.int32)


def train():
    print(f"Generating {N_SAMPLES} synthetic SSH connection samples...")
    X, y = generate_synthetic_data(N_SAMPLES)

    print(f"  Attackers (honeypot): {(y == 0).sum()}")
    print(f"  Real users:          {(y == 1).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    lr = LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        random_state=42,
    )
    gb = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=4,
        learning_rate=0.05,
        subsample=0.8,
        random_state=42,
    )
    cb = CatBoostClassifier(
        iterations=200,
        depth=4,
        learning_rate=0.05,
        random_seed=42,
        verbose=False,
        allow_writing_files=False,
    )
    ensemble = VotingClassifier(
        estimators=[("lr", lr), ("gb", gb), ("cb", cb)],
        voting="soft",
        weights=[1, 1.5, 2],
    )

    print("\nTraining VotingClassifier (LR + GradientBoost + CatBoost)...")
    ensemble.fit(X_train, y_train)

    cv_scores = cross_val_score(ensemble, X, y, cv=5)
    print(f"  5-fold CV accuracy: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")

    y_pred = ensemble.predict(X_test)
    y_proba = ensemble.predict_proba(X_test)[:, 1]

    print(f"\nTest set ({len(X_test)} samples):")
    print(classification_report(y_test, y_pred, target_names=["honeypot", "real"]))
    print(f"  ROC AUC: {roc_auc_score(y_test, y_proba):.3f}")

    joblib.dump(ensemble, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")

    # Quick sanity checks across all profile types
    print("\n--- Sanity checks (18 scenarios) ---")
    checks = [
        # ---- ATTACKERS (should be honeypot) ----
        # each: 18 base + [entropy, common_pw, repeating, rotating, subnet]
        ("Cred spray bot: 10att, 0.05s, 3 users", 0, [
            10.0, 3.0, 3.0, 0.03, 0.05, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 3.0, 4.0, 0.0, 0.0, 0.0,
            0.05, 1.0, 0.0, 1.0, 0.0,
        ]),
        ("Scanner: 1att, 0.03s, root, known IP", 0, [
            1.0, 1.0, 1.0, 0.03, 0.00, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 2.0, 1.0, 1.0, 0.0,
            0.03, 1.0, 0.0, 0.0, 0.0,
        ]),
        ("Brute slow: 8att, 1.5s, root", 0, [
            8.0, 1.0, 1.0, 0.80, 1.50, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 3.0, 1.0, 0.0, 0.0,
            0.08, 1.0, 0.0, 1.0, 0.0,
        ]),
        ("Username enum: 8att, 5 users", 0, [
            8.0, 5.0, 5.0, 0.10, 0.15, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 3.0, 2.0, 0.0, 0.0, 0.0,
            0.05, 1.0, 0.0, 1.0, 0.0,
        ]),
        ("Exploit: exec curl|bash, root", 0, [
            1.0, 1.0, 1.0, 0.50, 0.00, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 1.0, 3.0, 1.0, 0.0, 0.0,
            0.10, 0.0, 0.0, 0.0, 0.0,
        ]),
        ("Tor bot: 5att, 0.1s, root, is_tor", 0, [
            5.0, 2.0, 2.0, 0.10, 0.10, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 2.0, 22.0, 0.0, 0.0, 1.0,
            0.05, 1.0, 0.0, 1.0, 0.0,
        ]),
        ("Reconnect: 2att, rapid, 0.05s", 0, [
            2.0, 1.0, 1.0, 0.05, 0.10, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 2.0, 0.0, 0.0, 0.0,
            0.05, 1.0, 0.0, 1.0, 0.0,
        ]),
        ("Multi-method: key+pw+kbd, 5att", 0, [
            5.0, 2.0, 2.0, 0.50, 0.80, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 3.0, 3.0, 0.0, 0.0, 0.0,
            0.10, 1.0, 0.0, 1.0, 0.0,
        ]),
        ("Deprecated client: 3att, root", 0, [
            3.0, 2.0, 2.0, 0.30, 0.50, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 2.0, 2.0, 0.0, 0.0, 0.0,
            0.05, 1.0, 0.0, 1.0, 0.0,
        ]),

        # ---- REAL USERS (should be real) ----
        ("Admin: root+key, 3s, interactive", 1, [
            1.0, 1.0, 1.0, 3.00, 0.00, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 9.0, 0.0, 0.0, 0.0,
            0.72, 0.0, 0.0, 0.0, 0.0,
        ]),
        ("Password user: clean, 5s, 2att", 1, [
            2.0, 1.0, 0.0, 5.00, 8.00, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 10.0, 0.0, 0.0, 0.0,
            0.65, 0.0, 1.0, 0.0, 0.0,
        ]),
        ("DevOps: exec ls, key, clean", 1, [
            1.0, 1.0, 0.0, 1.50, 0.00, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 1.0, 10.0, 0.0, 0.0, 0.0,
            0.80, 0.0, 0.0, 0.0, 0.0,
        ]),
        ("Tor privacy: ubuntu+key, 4s", 1, [
            1.0, 1.0, 1.0, 4.00, 0.00, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 14.0, 0.0, 0.0, 1.0,
            0.78, 0.0, 0.0, 0.0, 0.0,
        ]),
        ("Weekend worker: clean, key, Sat", 1, [
            1.0, 1.0, 0.0, 2.00, 0.00, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 11.0, 1.0, 0.0, 0.0,
            0.70, 0.0, 0.0, 0.0, 0.0,
        ]),
        ("Password mgr: fast type, key, clean", 1, [
            1.0, 1.0, 0.0, 0.50, 0.25, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 9.0, 0.0, 0.0, 0.0,
            0.85, 0.0, 0.0, 0.0, 0.0,
        ]),
        ("VPN user: key, clean, business hrs", 1, [
            1.0, 1.0, 0.0, 2.00, 0.00, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 10.0, 0.0, 0.0, 1.0,
            0.75, 0.0, 0.0, 0.0, 0.0,
        ]),
        ("CI/CD: exec deploy, key, 0.3s", 1, [
            1.0, 1.0, 0.0, 0.30, 0.00, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 1.0, 14.0, 0.0, 0.0, 0.0,
            0.90, 0.0, 0.0, 0.0, 0.0,
        ]),
        ("Support: admin+key, human timing", 1, [
            1.0, 1.0, 1.0, 3.00, 0.00, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 10.0, 0.0, 0.0, 0.0,
            0.68, 0.0, 0.0, 0.0, 0.0,
        ]),
    ]

    errors = []
    for label, expected, feats in checks:
        prob = ensemble.predict_proba(np.array([feats], dtype=np.float64))[0]
        pred = 1 if prob[1] >= 0.5 else 0
        tag = "OK" if pred == expected else "FAIL"
        print("  [%s] %-45s real=%.3f  honeypot=%.3f" % (tag, label, prob[1], prob[0]))
        if pred != expected:
            errors.append(label)

    if errors:
        print("\n*** FAILURES: %d ***" % len(errors))
        for e in errors:
            print("  -", e)
    else:
        print("\nAll %d sanity checks PASSED" % len(checks))


if __name__ == "__main__":
    train()
