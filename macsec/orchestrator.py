"""Orchestrator: wires the agent team into a pipeline.

Pipeline stages:
  1. recon         InventoryCollectorAgent
  2. threat-intel  AppleCVEWebsiteAgent + KEVAgent + AppleReleasesAgent (parallel)
                   then NVDAgent (needs the inventory, rate-limited)
  3. correlation   MatcherAgent
  4. analysis      AnalyzerAgent -> LLMAnalystAgent
  5. hardening     HardeningAgent
  6. documentation ReporterAgent
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from macsec.agents.base import Agent, OrchestrationContext
from macsec.agents.epss import EPSSAgent
from macsec.agents.feeds import (AppleCVEWebsiteAgent, AppleReleasesAgent,
                                 KEVAgent, NVDAgent)
from macsec.agents.hardening import HardeningAgent
from macsec.agents.inventory import InventoryCollectorAgent
from macsec.agents.llm import LLMAnalystAgent
from macsec.agents.matcher import AnalyzerAgent, MatcherAgent
from macsec.agents.reporter import ReporterAgent
from macsec.config import Config
from macsec.history import HistoryStore
from macsec.models import Inventory
from macsec.score import compute_score

TEAM_ROSTER = [
    ("inventory-collector", "recon", "Collects hardware, OS build, software, security posture"),
    ("apple-cve-db", "threat-intel", "Decodes theevilbit/apple-cve-website Apple CVE database"),
    ("cisa-kev", "threat-intel", "Flags actively exploited CVEs from CISA KEV"),
    ("apple-releases", "threat-intel", "Tracks latest Apple security releases for macOS"),
    ("nvd-lookup", "threat-intel", "NVD CVE lookups for installed third-party software"),
    ("epss-enricher", "threat-intel", "FIRST.org EPSS exploit-probability scoring"),
    ("cve-matcher", "correlation", "Correlates CVEs with OS version and installed software"),
    ("risk-analyzer", "analysis", "Scores findings into P1-P4 priority tiers"),
    ("llm-analyst", "analysis", "Executive summary via local open-source model (Ollama)"),
    ("hardening-auditor", "hardening", "CIS-style macOS control audit with remediation"),
    ("scorekeeper", "analysis", "MacSec Score: composite 0-100 host security grade"),
    ("historian", "memory", "Persists scans to SQLite and diffs posture over time"),
    ("reporter", "documentation", "JSON / Markdown / HTML / SARIF reports"),
]


class Orchestrator:
    def __init__(self, cfg: Config, inventory_file: str | None = None):
        self.ctx = OrchestrationContext(config=cfg)
        self.inventory_file = inventory_file

    # ------------------------------------------------------------------

    def run_full_pipeline(self) -> dict[str, str]:
        self._stage_recon()
        self._stage_threat_intel(include_nvd=self.ctx.config.enable_nvd)
        self._stage_analysis()
        if self.ctx.config.enable_history:
            scan_id = HistoryStore().record_scan(self.ctx)
            self.ctx.log("historian", f"scan recorded as #{scan_id}", "ok")
        ReporterAgent(self.ctx).timed_run()
        return self.ctx.artifacts

    def run_audit_only(self) -> list:
        self._stage_recon()
        self._fetch_fast_feeds()
        checks = HardeningAgent(self.ctx).timed_run()
        return checks

    # ------------------------------------------------------------------

    def _stage_recon(self) -> None:
        if self.inventory_file:
            import json
            self.ctx.inventory = Inventory.from_dict(
                json.loads(open(self.inventory_file).read()))
            self.ctx.log("orchestrator",
                         f"loaded inventory from {self.inventory_file} "
                         f"({len(self.ctx.inventory.software)} software items)", "ok")
        else:
            InventoryCollectorAgent(self.ctx).timed_run()

    def _fetch_fast_feeds(self) -> None:
        """Apple DB, KEV and Apple releases are independent: fetch in parallel."""
        cfg = self.ctx.config
        agents: list[Agent] = [AppleCVEWebsiteAgent(self.ctx)]
        if cfg.enable_kev:
            agents.append(KEVAgent(self.ctx))
        if cfg.enable_apple_releases:
            agents.append(AppleReleasesAgent(self.ctx))
        with ThreadPoolExecutor(max_workers=len(agents)) as pool:
            futures = {pool.submit(a.timed_run): a for a in agents}
            for fut, agent in futures.items():
                try:
                    fut.result()
                except Exception as exc:
                    self.ctx.log(agent.name, f"feed unavailable: {exc}", "error")

    def _stage_threat_intel(self, include_nvd: bool) -> None:
        self._fetch_fast_feeds()
        if include_nvd:
            try:
                NVDAgent(self.ctx).timed_run()
            except Exception as exc:
                self.ctx.log("nvd-lookup", f"feed unavailable: {exc}", "error")

    def _stage_analysis(self) -> None:
        MatcherAgent(self.ctx).timed_run()
        if self.ctx.config.enable_epss:
            try:
                EPSSAgent(self.ctx).timed_run()
            except Exception as exc:
                self.ctx.log("epss-enricher", f"unavailable: {exc}", "error")
        AnalyzerAgent(self.ctx).timed_run()
        HardeningAgent(self.ctx).timed_run()
        score = compute_score(self.ctx.analysis, self.ctx.inventory)
        self.ctx.analysis.stats["macsec_score"] = score
        self.ctx.log("scorekeeper",
                     f"MacSec Score: {score['score']}/100 ({score['grade']})", "ok")
        if self.ctx.config.enable_llm:
            LLMAnalystAgent(self.ctx).timed_run()
        else:
            self.ctx.analysis.llm_summary = LLMAnalystAgent(self.ctx)._rule_based_summary()
            self.ctx.analysis.llm_model = "rule-based (LLM disabled)"
