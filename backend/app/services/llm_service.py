"""
LLM Service: integrates with Ollama to generate threat explanations,
attack type classification, and mitigation recommendations.
"""
import httpx
import json
import logging
from typing import Dict, Any, Optional
from app.core.config import settings

logger = logging.getLogger(__name__)


THREAT_ANALYSIS_PROMPT = """You are a senior cybersecurity analyst at a Security Operations Center (SOC).
Analyze the following security anomaly and provide a structured threat assessment.

Security Event Details:
{context}

Provide your analysis in the following JSON format:
{{
  "explanation": "Clear explanation of what this anomaly indicates (2-3 sentences)",
  "attack_type": "Most likely attack type (e.g., Brute Force, Port Scan, DDoS, SQL Injection, Lateral Movement, Data Exfiltration, etc.)",
  "confidence": "High/Medium/Low",
  "ttps": ["List of MITRE ATT&CK TTPs if applicable"],
  "mitigation_steps": [
    "Immediate action 1",
    "Immediate action 2",
    "Long-term recommendation 1"
  ],
  "references": ["CVE or threat intelligence references if applicable"]
}}

Respond with ONLY the JSON object, no additional text."""


class LLMService:
    """
    Service for generating AI-powered threat explanations using Ollama.
    Handles connection errors gracefully with fallback responses.
    """

    def __init__(self):
        self.base_url = settings.OLLAMA_BASE_URL
        self.model = settings.OLLAMA_MODEL
        self.timeout = settings.OLLAMA_TIMEOUT

    async def _call_ollama(self, prompt: str) -> Optional[str]:
        """Make an async call to the Ollama API."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,  # Low temperature for consistent security analysis
                        "top_p": 0.9,
                        "num_predict": 1024,
                    },
                },
            )
            response.raise_for_status()
            return response.json().get("response", "")

    async def analyze_threat(
        self,
        anomaly_data: Dict[str, Any],
        log_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a threat explanation for an anomaly using the LLM.
        Falls back to a structured placeholder if Ollama is unavailable.
        """
        context_parts = []

        if log_data:
            context_parts.append(f"Source IP: {log_data.get('source_ip', 'Unknown')}")
            context_parts.append(f"Destination IP: {log_data.get('destination_ip', 'Unknown')}")
            context_parts.append(f"Destination Port: {log_data.get('destination_port', 'Unknown')}")
            context_parts.append(f"Protocol: {log_data.get('protocol', 'Unknown')}")
            context_parts.append(f"Event Type: {log_data.get('event_type', 'Unknown')}")
            context_parts.append(f"Severity: {log_data.get('severity', 'Unknown')}")
            if log_data.get("message"):
                context_parts.append(f"Log Message: {log_data.get('message')}")

        context_parts.append(f"Anomaly Score: {anomaly_data.get('anomaly_score', 0):.3f}")
        if anomaly_data.get("rule_name"):
            context_parts.append(f"Detection Rule: {anomaly_data.get('rule_name')}")
        if anomaly_data.get("description"):
            context_parts.append(f"Alert Description: {anomaly_data.get('description')}")

        context = "\n".join(context_parts)
        prompt = THREAT_ANALYSIS_PROMPT.format(context=context)

        try:
            raw_response = await self._call_ollama(prompt)

            if raw_response:
                # Extract JSON from the response
                json_start = raw_response.find("{")
                json_end = raw_response.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = raw_response[json_start:json_end]
                    parsed = json.loads(json_str)
                    return {
                        "explanation": parsed.get("explanation", "Analysis completed"),
                        "attack_type": parsed.get("attack_type", "Unknown"),
                        "confidence": parsed.get("confidence", "Low"),
                        "mitigation_steps": parsed.get("mitigation_steps", []),
                        "references": parsed.get("references", []),
                        "ttps": parsed.get("ttps", []),
                        "source": "ollama",
                    }

        except httpx.ConnectError:
            logger.warning("Ollama service unavailable; using fallback threat analysis")
        except httpx.TimeoutException:
            logger.warning("Ollama request timed out; using fallback threat analysis")
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse LLM response: {e}")
        except Exception as e:
            logger.error(f"Unexpected LLM error: {e}")

        # Fallback: rule-based placeholder when Ollama is unavailable
        return self._generate_fallback_analysis(anomaly_data, log_data)

    def _generate_fallback_analysis(
        self,
        anomaly_data: Dict[str, Any],
        log_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a basic threat analysis without LLM when Ollama is unavailable.
        Uses rule names and event types to provide contextual guidance.
        """
        rule_name = anomaly_data.get("rule_name", "")
        score = anomaly_data.get("anomaly_score", 0)

        analyses = {
            "brute_force_login": {
                "attack_type": "Brute Force Authentication Attack",
                "explanation": (
                    "Multiple failed authentication attempts detected from the same source IP, "
                    "indicating an automated password guessing attack or credential stuffing attempt."
                ),
                "mitigation_steps": [
                    "Block source IP immediately at the firewall",
                    "Enable account lockout policy after 3-5 failed attempts",
                    "Implement multi-factor authentication (MFA)",
                    "Review authentication logs for compromised accounts",
                    "Consider CAPTCHA on login endpoints",
                ],
            },
            "port_scan": {
                "attack_type": "Network Reconnaissance / Port Scanning",
                "explanation": (
                    "Systematic connection attempts across multiple ports from a single IP indicate "
                    "network reconnaissance — a common precursor to targeted attacks."
                ),
                "mitigation_steps": [
                    "Block source IP at perimeter firewall",
                    "Enable port scan detection on IDS/IPS",
                    "Review and restrict firewall rules",
                    "Check for any successful connections from this IP",
                    "Report IP to threat intelligence feeds",
                ],
            },
            "ddos_flood": {
                "attack_type": "Distributed Denial of Service (DDoS)",
                "explanation": (
                    "Extremely high request rate from a single IP suggests a DDoS flood attack "
                    "designed to overwhelm services and cause availability disruption."
                ),
                "mitigation_steps": [
                    "Activate DDoS mitigation systems immediately",
                    "Apply rate limiting and traffic throttling",
                    "Contact upstream ISP for traffic filtering",
                    "Enable CDN protection (Cloudflare, AWS Shield)",
                    "Monitor bandwidth and server health metrics",
                ],
            },
            "data_exfiltration": {
                "attack_type": "Data Exfiltration",
                "explanation": (
                    "Unusually large outbound data transfer detected, which may indicate "
                    "unauthorized data exfiltration by a threat actor or malicious insider."
                ),
                "mitigation_steps": [
                    "Immediately block outbound connections from this host",
                    "Preserve forensic evidence (network captures, logs)",
                    "Identify what data was transferred and to whom",
                    "Initiate incident response procedures",
                    "Audit user accounts and access permissions",
                ],
            },
        }

        specific = analyses.get(rule_name, {})

        return {
            "explanation": specific.get(
                "explanation",
                f"Anomalous behavior detected with score {score:.3f}. "
                "Manual investigation recommended to determine the nature of this activity."
            ),
            "attack_type": specific.get("attack_type", "Suspicious Activity"),
            "confidence": "High" if score > 0.8 else "Medium" if score > 0.6 else "Low",
            "mitigation_steps": specific.get("mitigation_steps", [
                "Investigate the source IP and recent activity",
                "Review related log entries for context",
                "Consider blocking the source IP if threat is confirmed",
                "Escalate to security team for further analysis",
            ]),
            "references": [],
            "ttps": [],
            "source": "fallback",
        }

    async def check_availability(self) -> bool:
        """Check if Ollama service is available."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                return response.status_code == 200
        except Exception:
            return False


# Application-scoped singleton
llm_service = LLMService()
