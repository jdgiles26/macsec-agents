"""End-to-end pipeline tests against recorded real feed fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from macsec.agents.base import OrchestrationContext
from macsec.agents.feeds import AppleCVEWebsiteAgent, KEVAgent
from macsec.agents.hardening import HardeningAgent
from macsec.agents.llm import LLMAnalystAgent
from macsec.agents.matcher import AnalyzerAgent, MatcherAgent
from macsec.agents.reporter import ReporterAgent
from macsec.config import Config
from macsec.models import Inventory

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def cfg(tmp_path, monkeypatch) -> Config:
    monkeypatch.setenv("MACSEC_CACHE_DIR", str(tmp_path / "cache"))
    c = Config()
    c.offline = True
    c.enable_nvd = False
    c.enable_llm = True   # falls back to rule-based summary without Ollama
    c.output_dir = str(tmp_path / "reports")
    return c


@pytest.fixture()
def ctx(cfg) -> OrchestrationContext:
    c = OrchestrationContext(config=cfg)
    c.inventory = Inventory.from_dict(
        json.loads((FIXTURES / "inventory_macmini_m2.json").read_text()))
    return c


def _seed_cache(cfg: Config) -> None:
    """Pre-populate the HTTP disk cache with the recorded fixtures."""
    from macsec.utils import cache_dir
    import hashlib, time
    for url, fixture in ((cfg.apple_cve_db_url, "apple_db_sample.json"),
                         (cfg.cisa_kev_url, "kev_sample.json")):
        key = hashlib.sha256(url.encode()).hexdigest()[:32]
        (cache_dir() / f"{key}.bin").write_bytes((FIXTURES / fixture).read_bytes())
        (cache_dir() / f"{key}.meta.json").write_text(json.dumps({"ts": time.time()}))


def test_apple_db_decoder(cfg, ctx):
    _seed_cache(cfg)
    feed = AppleCVEWebsiteAgent(ctx).timed_run()
    assert feed.records, "decoder returned no CVEs"
    by_id = {r.cve_id: r for r in feed.records}
    # real record from macOS Tahoe 26.7.1 (2026-09-28)
    rec = by_id["CVE-2026-86950"]
    assert rec.exploited is True
    assert rec.cvss == 8.8
    assert rec.component == "CoreGraphics"
    assert "macOS" in rec.platforms
    assert any("26.7.1" in v for v in rec.fixed_versions)


def test_kev_decoder(cfg, ctx):
    _seed_cache(cfg)
    feed = KEVAgent(ctx).timed_run()
    assert {r.cve_id for r in feed.records} == {"CVE-2023-41064", "CVE-2021-30860"}
    assert all(r.exploited for r in feed.records)


def test_full_pipeline(cfg, ctx):
    _seed_cache(cfg)
    AppleCVEWebsiteAgent(ctx).timed_run()
    KEVAgent(ctx).timed_run()

    matches = MatcherAgent(ctx).timed_run()
    assert matches, "macOS 26.6 should match CVEs fixed in Tahoe 26.7/26.7.1"
    exploited = [m for m in matches if m.cve.cve_id == "CVE-2026-86950"]
    assert exploited and exploited[0].cve.exploited
    assert exploited[0].match_kind == "fixed-version"
    assert exploited[0].confidence == "high"

    risks = AnalyzerAgent(ctx).timed_run()
    assert risks[0].tier == "P1-CRITICAL"
    exploited_risks = [r for r in risks if r.match.cve.exploited]
    assert exploited_risks and all(r.tier == "P1-CRITICAL" for r in exploited_risks)
    # the exploited finding is ranked inside the P1-CRITICAL group at the top
    first = {r.match.cve.cve_id: i for i, r in enumerate(risks)}
    n_p1 = sum(1 for r in risks if r.tier == "P1-CRITICAL")
    assert first["CVE-2026-86950"] < n_p1

    checks = HardeningAgent(ctx).timed_run()
    by_id = {c.check_id: c for c in checks}
    assert by_id["MACSEC-SIP-001"].status == "pass"
    assert by_id["MACSEC-FV-001"].status == "fail"       # FileVault off in fixture
    assert by_id["MACSEC-FW-001"].status == "fail"       # firewall off in fixture

    summary = LLMAnalystAgent(ctx).timed_run()
    assert "CVE-2026-86950" in summary

    artifacts = ReporterAgent(ctx).timed_run()
    assert set(artifacts) == {"json", "md", "html", "sarif"}
    payload = json.loads(Path(artifacts["json"]).read_text())
    assert payload["inventory"]["chip"] == "Apple M2"
    assert payload["stats"]["exploited"] >= 1
    sarif = json.loads(Path(artifacts["sarif"]).read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"], "SARIF export contains no results"
    md = Path(artifacts["md"]).read_text()
    assert "CVE-2026-86950" in md
    html = Path(artifacts["html"]).read_text()
    assert "EXPLOITED" in html


def test_patched_os_matches_nothing(cfg, ctx):
    """A fully patched Tahoe 26.7.1 host must not match CVEs fixed in 26.7/26.7.1."""
    _seed_cache(cfg)
    ctx.inventory.macos_product_version = "26.7.1"
    AppleCVEWebsiteAgent(ctx).timed_run()
    matches = MatcherAgent(ctx).timed_run()
    macos_matches = [m for m in matches if m.match_kind == "fixed-version"]
    assert macos_matches == []


def test_remediation_script(ctx):
    checks = HardeningAgent(ctx).run()
    script = HardeningAgent.remediation_script(checks)
    assert script.startswith("#!/bin/zsh")
    assert "MACSEC-FV-001" in script
    assert "MACSEC-SIP-001" not in script  # passing control excluded
