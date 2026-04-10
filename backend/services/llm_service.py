"""
OpenAI-compatible LLM service for AI-powered threat analysis.

Supports any OpenAI-compatible API (OpenAI, Azure OpenAI, Ollama, vLLM, LM Studio, etc.)
by configuring LLM_BASE_URL and LLM_API_KEY.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from openai import AsyncOpenAI

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert cybersecurity threat analyst for the EvilTwin SDN Deception Platform.
You analyze honeypot session data, attacker behaviors, and network events to provide actionable threat intelligence.

Your responsibilities:
- Analyze attacker commands and behaviors from SSH/HTTP/FTP honeypot sessions
- Identify Tactics, Techniques, and Procedures (TTPs) mapped to MITRE ATT&CK
- Extract Indicators of Compromise (IoCs): IPs, domains, hashes, URLs, user agents
- Assess risk levels and recommend defensive actions
- Explain attacker intent and potential impact in clear, concise language

Always structure your analysis with:
1. Executive Summary (2-3 sentences)
2. Risk Assessment (Critical/High/Medium/Low with justification)
3. TTPs identified (MITRE ATT&CK IDs where possible)
4. IoC indicators found
5. Recommended defensive actions

Be precise, factual, and avoid speculation. If data is insufficient, state what additional data would be needed."""

SESSION_ANALYSIS_PROMPT = """Analyze the following honeypot session data and provide a structured threat assessment.

Session Details:
- Session ID: {session_id}
- Attacker IP: {attacker_ip}
- Honeypot: {honeypot}
- Protocol: {protocol}
- Start Time: {start_time}
- End Time: {end_time}
- Threat Score: {threat_score}
- Threat Level: {threat_level}
- VPN Detected: {vpn_detected}
- Country: {country}
- ISP: {isp}

Commands Executed ({cmd_count} total):
{commands}

Credentials Attempted ({cred_count} total):
{credentials}

Malware Hashes: {malware_hashes}

{additional_context}

Provide your structured threat analysis following the format specified in your system prompt.
Also extract:
- All IoC indicators (IPs, domains, hashes, URLs, filenames)
- All TTPs with MITRE ATT&CK IDs where identifiable
- Confidence score (0.0-1.0) for your overall assessment"""


class LLMService:
    """OpenAI-compatible LLM client for threat analysis."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        max_tokens: int = 1024,
        temperature: float = 0.2,
    ) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.client = AsyncOpenAI(api_key=api_key, base_url=base_url)

    async def close(self) -> None:
        await self.client.close()

    async def analyze_session(
        self,
        session: Any,
        profile: Any,
        additional_context: str = "",
    ) -> dict[str, Any]:
        """Analyze a honeypot session and return structured threat intelligence."""
        commands_text = ""
        for i, cmd in enumerate((getattr(session, "commands", None) or [])[:50], 1):
            ts = cmd.get("timestamp", "?")
            command = cmd.get("command", "?")
            output = cmd.get("output", "")
            commands_text += f"  {i}. [{ts}] $ {command}"
            if output:
                commands_text += f"\n     → {output[:200]}"
            commands_text += "\n"
        if not commands_text:
            commands_text = "  (none recorded)"

        creds_text = ""
        for cred in (getattr(session, "credentials_tried", None) or [])[:20]:
            user = cred.get("username", "?")
            pwd = cred.get("password", "?")
            success = "✓" if cred.get("success") else "✗"
            creds_text += f"  {success} {user}:{pwd}\n"
        if not creds_text:
            creds_text = "  (none recorded)"

        malware = ", ".join(getattr(session, "malware_hashes", None) or []) or "(none)"

        user_message = SESSION_ANALYSIS_PROMPT.format(
            session_id=getattr(session, "id", "unknown"),
            attacker_ip=str(getattr(session, "attacker_ip", "unknown")),
            honeypot=getattr(session, "honeypot", "unknown"),
            protocol=getattr(session, "protocol", "unknown"),
            start_time=getattr(session, "start_time", "unknown"),
            end_time=getattr(session, "end_time", "unknown"),
            threat_score=getattr(profile, "threat_score", 0.0),
            threat_level=getattr(profile, "threat_level", 0),
            vpn_detected=getattr(profile, "vpn_detected", False),
            country=getattr(profile, "country", "unknown"),
            isp=getattr(profile, "isp", "unknown"),
            cmd_count=len(getattr(session, "commands", None) or []),
            commands=commands_text,
            cred_count=len(getattr(session, "credentials_tried", None) or []),
            credentials=creds_text,
            malware_hashes=malware,
            additional_context=f"Additional Context: {additional_context}" if additional_context else "",
        )

        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            max_tokens=self.max_tokens,
            temperature=self.temperature,
        )

        content = response.choices[0].message.content or ""
        tokens_used = response.usage.total_tokens if response.usage else 0

        # Parse structured data from the response
        result = self._parse_analysis(content)
        result["model_used"] = self.model
        result["tokens_used"] = tokens_used
        result["raw_analysis"] = content

        return result

    async def chat(
        self,
        message: str,
        conversation_history: list[dict] | None = None,
        session_context: str | None = None,
    ) -> dict[str, Any]:
        """Handle conversational threat intelligence queries."""
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]

        if session_context:
            messages.append({
                "role": "system",
                "content": f"Current session context:\n{session_context}",
            })

        if conversation_history:
            for msg in conversation_history[-10:]:  # Keep last 10 messages
                role = msg.get("role", "user")
                if role in ("user", "assistant"):
                    messages.append({"role": role, "content": msg.get("content", "")})

        messages.append({"role": "user", "content": message})

        response = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
        )

        content = response.choices[0].message.content or ""
        tokens_used = response.usage.total_tokens if response.usage else 0

        return {
            "reply": content,
            "model_used": self.model,
            "tokens_used": tokens_used,
        }

    def _parse_analysis(self, content: str) -> dict[str, Any]:
        """Extract structured fields from the LLM's analysis text."""
        lines = content.lower()

        # Extract confidence
        confidence = 0.7  # default
        for line in content.split("\n"):
            lower = line.lower()
            if "confidence" in lower:
                for word in line.split():
                    try:
                        val = float(word.strip("(),%"))
                        if 0 <= val <= 1:
                            confidence = val
                            break
                        elif 1 < val <= 100:
                            confidence = val / 100
                            break
                    except ValueError:
                        continue

        # Extract risk assessment
        risk = "medium"
        for level in ["critical", "high", "medium", "low"]:
            if "risk" in lines and level in lines:
                risk = level
                break

        # Extract TTPs (MITRE ATT&CK patterns like T1234, T1234.001)
        ttps = list(set(re.findall(r"T\d{4}(?:\.\d{3})?", content)))

        # Extract IoCs — basic patterns
        iocs = []
        # IP addresses
        ip_pattern = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", content)
        iocs.extend(list(set(ip_pattern)))
        # SHA256 hashes
        hash_pattern = re.findall(r"\b[a-fA-F0-9]{64}\b", content)
        iocs.extend(list(set(hash_pattern)))
        # MD5 hashes
        md5_pattern = re.findall(r"\b[a-fA-F0-9]{32}\b", content)
        iocs.extend(list(set(md5_pattern)))

        # Extract recommended actions
        actions = []
        in_actions = False
        for line in content.split("\n"):
            stripped = line.strip()
            if "recommend" in stripped.lower() and ("action" in stripped.lower() or "step" in stripped.lower()):
                in_actions = True
                continue
            if in_actions:
                if stripped.startswith(("-", "•", "*")) or (stripped and stripped[0].isdigit() and "." in stripped[:4]):
                    actions.append(stripped.lstrip("-•* 0123456789.").strip())
                elif not stripped and actions:
                    in_actions = False

        # Summary = first paragraph
        paragraphs = [p.strip() for p in content.split("\n\n") if p.strip()]
        summary = paragraphs[0] if paragraphs else content[:500]

        return {
            "summary": summary,
            "risk_assessment": risk,
            "recommended_actions": actions[:10],
            "ioc_indicators": iocs[:50],
            "ttps": ttps[:20],
            "confidence": confidence,
        }
