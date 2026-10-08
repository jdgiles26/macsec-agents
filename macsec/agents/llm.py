"""LLMAnalystAgent: optional open-source model analysis via a local Ollama server.

Fully optional and offline-capable: if no Ollama server answers, the agent
produces a deterministic rule-based executive summary instead and says so in
the report. No finding is ever silently dropped.
"""

from __future__ import annotations

import requests

from macsec.agents.base import Agent


class LLMAnalystAgent(Agent):
    name = "llm-analyst"
    role = "analysis"
    description = "Summarizes top findings with a local open-source model (Ollama)"

    def run(self) -> str:
        analysis = self.ctx.analysis
        prompt = self._build_prompt()
        if self._ollama_available():
            try:
                summary = self._ollama_generate(prompt)
                analysis.llm_model = self.cfg.ollama_model
                analysis.llm_summary = summary
                self.log(f"analysis written by {self.cfg.ollama_model}")
                return summary
            except requests.RequestException as exc:
                self.log(f"ollama generation failed ({exc}), falling back to rules", "warn")
        else:
            self.log("no Ollama server reachable, using rule-based summary", "warn")
        summary = self._rule_based_summary()
        analysis.llm_model = "rule-based (no LLM)"
        analysis.llm_summary = summary
        return summary

    # ------------------------------------------------------------ ollama

    def _ollama_available(self) -> bool:
        try:
            r = requests.get(f"{self.cfg.ollama_url}/api/tags", timeout=3)
            return r.status_code == 200
        except requests.RequestException:
            return False

    def _ollama_generate(self, prompt: str) -> str:
        r = requests.post(
            f"{self.cfg.ollama_url}/api/generate",
            json={"model": self.cfg.ollama_model, "prompt": prompt, "stream": False},
            timeout=self.cfg.llm_timeout,
        )
        r.raise_for_status()
        return r.json().get("response", "").strip()

    # ------------------------------------------------------------ prompts

    def _build_prompt(self) -> str:
        inv = self.ctx.inventory
        risks = self.ctx.analysis.risks[: self.cfg.llm_max_findings]
        findings = "\n".join(
            f"- [{r.tier}] {r.match.cve.cve_id} (CVSS {r.match.cve.cvss or 'n/a'}"
            f"{', EXPLOITED' if r.match.cve.exploited else ''}) "
            f"affects {r.match.target} {r.match.target_version}: "
            f"{(r.match.cve.impact or r.match.cve.description)[:160]}"
            for r in risks
        ) or "- No CVE matches."
        hardening = "\n".join(
            f"- [{c.status.upper()}] {c.title}" for c in self.ctx.analysis.hardening
        )
        return (
            "You are a macOS security analyst. Write a concise executive summary "
            "(max 200 words) for the owner of this Mac, then a prioritized action "
            "list. Be specific, no filler.\n\n"
            f"Host: {inv.model if inv else '?'} {inv.chip if inv else ''}, "
            f"macOS {inv.macos_product_version if inv else '?'}\n\n"
            f"Top findings:\n{findings}\n\nHardening controls:\n{hardening}\n"
        )

    def _rule_based_summary(self) -> str:
        a = self.ctx.analysis
        s = a.stats
        inv = self.ctx.inventory
        host = f"{inv.model} ({inv.chip}), macOS {inv.macos_product_version}" if inv else "unknown host"
        p1, p2 = s.get("by_tier", {}).get("P1-CRITICAL", 0), s.get("by_tier", {}).get("P2-HIGH", 0)
        exploited = s.get("exploited", 0)
        fails = s.get("hardening_fail", 0)
        lines = [
            f"Host {host} has {s.get('total_matches', 0)} CVE matches: "
            f"{p1} critical-priority, {p2} high-priority; {exploited} are actively exploited in the wild.",
        ]
        if exploited:
            ids = [r.match.cve.cve_id for r in a.risks if r.match.cve.exploited][:5]
            lines.append("Immediately patch exploited CVEs: " + ", ".join(ids) + ".")
        if fails:
            names = [c.title for c in a.hardening if c.status == "fail"][:4]
            lines.append(f"{fails} hardening controls failing, notably: " + "; ".join(names) + ".")
        if not exploited and not fails and p1 == 0:
            lines.append("No urgent issues detected; keep automatic updates enabled.")
        lines.append("Rule-based summary (start an Ollama server with an open model for LLM analysis).")
        return " ".join(lines)
