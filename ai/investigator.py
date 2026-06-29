from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from ai_explainer import get_provider, AIProviderConfig

logger = logging.getLogger(__name__)


class AIInvestigator:
    def __init__(self, config: AIProviderConfig):
        self.config = config
        self.provider = get_provider(config)

    def _build_context(self, case: Dict[str, Any], memory_context: Optional[Dict[str, Any]] = None) -> str:
        parts = []
        parts.append(f"Verdict: {case.get('verdict', 'UNKNOWN')}")
        parts.append(f"Score: {case.get('score', 0)}/20")
        parts.append(f"Confidence: {case.get('confidence', 'LOW')}")
        reasons = case.get("reasons", [])
        if reasons:
            parts.append("Detection Reasons:")
            for r in reasons:
                parts.append(f"  - {r}")
        iocs = case.get("iocs", {})
        if iocs:
            parts.append("IOCs:")
            for ioc_type, values in iocs.items():
                if values:
                    parts.append(f"  {ioc_type}: {', '.join(values[:5])}")
        if memory_context:
            if memory_context.get("history"):
                parts.append("Previous Related Cases:")
                for h in memory_context["history"][:3]:
                    parts.append(f"  - {h.get('case_id', '?')} ({h.get('verdict', '?')}, score={h.get('score', '?')})")
            if memory_context.get("similar"):
                parts.append("Similar Cases:")
                for s in memory_context["similar"][:3]:
                    parts.append(f"  - {s.get('case_id', '?')} (similarity={int((s.get('similarity', 0) or 0)*100)}%)")
        return "\n".join(parts)

    def explain(self, case: Dict[str, Any], memory_context: Optional[Dict[str, Any]] = None) -> str:
        context = self._build_context(case, memory_context)
        prompt = (
            "You are a cybersecurity analyst assisting a SOC team. "
            "Based on the investigation results below, explain why this email is suspicious or malicious. "
            "Be concise, technical, and actionable. Include specific indicators "
            "(SPF/DKIM/DMARC, infrastructure, IOCs, similarity to previous cases if provided).\n\n"
            f"{context}\n\nExplanation:"
        )
        return self._ask(prompt)

    def story(self, case: Dict[str, Any], memory_context: Optional[Dict[str, Any]] = None) -> str:
        context = self._build_context(case, memory_context)
        prompt = (
            "You are a cybersecurity analyst. Write a narrative attack story for this phishing email. "
            "Describe the likely attacker workflow, infrastructure, social engineering tactics, and victim impact. "
            "Make it suitable for an incident report.\n\n"
            f"{context}\n\nAttack Story:"
        )
        return self._ask(prompt)

    def campaign(self, case: Dict[str, Any], memory_context: Optional[Dict[str, Any]] = None) -> str:
        context = self._build_context(case, memory_context)
        prompt = (
            "You are a threat intelligence analyst. Analyze whether this email belongs to a known or emerging campaign. "
            "Compare against previous cases and similar campaigns if provided. Assess confidence and list reasons.\n\n"
            f"{context}\n\nCampaign Analysis:"
        )
        return self._ask(prompt)

    def compare(self, case_a: Dict[str, Any], case_b: Dict[str, Any]) -> str:
        prompt = (
            "You are a cybersecurity analyst. Compare these two phishing cases side by side. "
            "Identify shared infrastructure, templates, tactics, and likely attribution. "
            "State similarity and confidence.\n\n"
            f"Case A:\n{self._build_context(case_a)}\n\n"
            f"Case B:\n{self._build_context(case_b)}\n\nComparison:"
        )
        return self._ask(prompt)

    def predict(self, case: Dict[str, Any], memory_context: Optional[Dict[str, Any]] = None) -> str:
        context = self._build_context(case, memory_context)
        prompt = (
            "You are a SOC analyst. Given this investigation and historical patterns, predict the attacker's next actions, "
            "likely targets, and recommended proactive defenses. Be specific.\n\n"
            f"{context}\n\nPrediction & Recommendations:"
        )
        return self._ask(prompt)

    def recommend(self, case: Dict[str, Any]) -> str:
        context = self._build_context(case)
        prompt = (
            "You are a SOC manager. Provide prioritized, actionable recommendations for this phishing incident. "
            "Include immediate containment, investigation steps, user notification, and long-term hardening.\n\n"
            f"{context}\n\nRecommendations:"
        )
        return self._ask(prompt)

    def ioc_analysis(self, case: Dict[str, Any]) -> str:
        context = self._build_context(case)
        prompt = (
            "You are a threat intelligence analyst. Analyze the IOCs in this case. "
            "Explain the significance of each indicator, prioritize them, and suggest enrichment sources.\n\n"
            f"{context}\n\nIOC Analysis:"
        )
        return self._ask(prompt)

    def graph_story(self, case: Dict[str, Any], memory_context: Optional[Dict[str, Any]] = None) -> str:
        context = self._build_context(case, memory_context)
        prompt = (
            "You are a SOC analyst. Describe the investigation knowledge graph for this case. "
            "Identify the central nodes (email, domains, IPs, campaigns) and their relationships. "
            "Explain what the graph reveals about the threat actor and campaign structure.\n\n"
            f"{context}\n\nKnowledge Graph Story:"
        )
        return self._ask(prompt)

    def timeline(self, case: Dict[str, Any], memory_context: Optional[Dict[str, Any]] = None) -> str:
        context = self._build_context(case, memory_context)
        prompt = (
            "You are a forensic analyst. Build a timeline of events for this phishing incident based on the evidence. "
            "Include email creation, sending, delivery, and any known attacker actions.\n\n"
            f"{context}\n\nTimeline:"
        )
        return self._ask(prompt)

    def similar_analysis(self, case: Dict[str, Any], similar_cases: List[Dict[str, Any]]) -> str:
        context = self._build_context(case)
        similar_text = "\n".join([
            f"- {s.get('case_id', '?')} verdict={s.get('verdict', '?')} score={s.get('score', '?')}"
            for s in similar_cases[:5]
        ])
        prompt = (
            "You are a threat intelligence analyst. Analyze these similar cases alongside the current case. "
            "Identify patterns, shared TTPs, and campaign links. State your confidence.\n\n"
            f"Current Case:\n{context}\n\nSimilar Cases:\n{similar_text}\n\nSimilarity Analysis:"
        )
        return self._ask(prompt)

    def _ask(self, prompt: str) -> str:
        if self.config.provider == "ollama":
            return self._ask_ollama(prompt)
        if self.config.provider == "openai":
            return self._ask_openai(prompt)
        if self.config.provider == "anthropic":
            return self._ask_anthropic(prompt)
        return "Unsupported AI provider."

    def _ask_ollama(self, prompt: str) -> str:
        url = f"{self.config.base_url}/api/generate"
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": True,
            "options": {"num_predict": 400, "temperature": 0.3},
        }
        import requests
        resp = requests.post(url, json=payload, timeout=120, stream=True)
        resp.raise_for_status()
        full = []
        for line in resp.iter_lines(decode_unicode=True):
            if line:
                data = json.loads(line)
                if "response" in data:
                    chunk = data["response"]
                    full.append(chunk)
        return "".join(full)

    def _ask_openai(self, prompt: str) -> str:
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ImportError("openai package required. Install with: pip install ai-phishing-investigator[ai]") from exc
        client = OpenAI(api_key=self.config.api_key)
        response = client.chat.completions.create(
            model=self.config.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=400,
        )
        return response.choices[0].message.content or "No response."

    def _ask_anthropic(self, prompt: str) -> str:
        try:
            from anthropic import Anthropic
        except ImportError as exc:
            raise ImportError("anthropic package required. Install with: pip install ai-phishing-investigator[ai]") from exc
        client = Anthropic(api_key=self.config.api_key)
        message = client.messages.create(
            model=self.config.model,
            max_tokens=400,
            temperature=0.3,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text
