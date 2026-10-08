"""Tests for the five v1.1 upgrades: EPSS, history/diff, MacSec Score,
unsigned-app auditor, SARIF export."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from macsec.agents.base import OrchestrationContext
from macsec.agents.epss import EPSSAgent
from macsec.agents.hardening import HardeningAgent
from macsec.agents.matcher import AnalyzerAgent
from macsec.config import Config
from macsec.history import HistoryStore
from macsec.models import (AnalysisResult, CVERecord, HardeningCheck, Inventory,
                           Match, RiskAssessment)
from macsec.sarif import build_sarif
from macsec.score import compute_score

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def cfg(tmp_path, monkeypatch) -> Config:
    monkeypatch.setenv("MACSEC_CACHE_DIR", str(tmp_path / "cache"))
    c = Config()
    c.offline = True
    c.enable_nvd = False
    return c


def _inv() -> Inventory:
    return Inventory.from_dict(
        json.loads((FIXTURES / "inventory_macmini_m2.json").read_text()))


def _ctx_with_matches(cfg) -> OrchestrationContext:
    """Context with three matches whose CVEs have recorded EPSS fixture data."""
    ctx = OrchestrationContext(config=cfg)
    ctx.inventory = _inv()
    matches = []
    for cve_id, cvss, exploited in (("CVE-2026-86950", 8.8, True),
                                    ("CVE-2026-65414", 9.8, False),
                                    ("CVE-2026-65381", 8.8, False)):
        rec = CVERecord(cve_id=cve_id, source="apple-cve-website", cvss=cvss,
                        exploited=exploited, platforms=["macOS"])
        matches.append(Match(cve=rec, target="macOS", target_version="26.6",
                             match_kind="fixed-version", confidence="high"))
    ctx.analysis.matches = matches
    return ctx


# ------------------------------------------------------------- 1. EPSS

def test_epss_enrichment(cfg, monkeypatch):
    ctx = _ctx_with_matches(cfg)
    payload = (FIXTURES / "epss_sample.json").read_bytes()
    monkeypatch.setattr("macsec.agents.epss.http_get", lambda *a, **k: payload)

    enriched = EPSSAgent(ctx).run()
    assert enriched == 3
    by_id = {m.cve.cve_id: m.cve for m in ctx.analysis.matches}
    assert by_id["CVE-2026-86950"].extra["epss"] == pytest.approx(0.01242)
    assert by_id["CVE-2026-65381"].extra["epss_percentile"] == pytest.approx(0.26985)


def test_epss_feed_failure_degrades_gracefully(cfg, monkeypatch):
    ctx = _ctx_with_matches(cfg)
    def boom(*a, **k):
        raise RuntimeError("network down")
    monkeypatch.setattr("macsec.agents.epss.http_get", boom)
    assert EPSSAgent(ctx).run() == 0   # pipeline continues, no EPSS data


def test_epss_high_probability_boosts_score(cfg):
    ctx = _ctx_with_matches(cfg)
    for m in ctx.analysis.matches:
        if m.cve.cve_id == "CVE-2026-65414":
            m.cve.extra["epss"] = 0.62
    risks = AnalyzerAgent(ctx).run()
    boosted = next(r for r in risks if r.match.cve.cve_id == "CVE-2026-65414")
    assert any("EPSS" in f for f in boosted.factors)


# ------------------------------------------------------------- 2. history

def _analysis_with(risks_spec, score_val=80.0):
    a = AnalysisResult()
    for cve_id, target, tier, sc, ex in risks_spec:
        rec = CVERecord(cve_id=cve_id, source="apple-cve-website", exploited=ex)
        m = Match(cve=rec, target=target, target_version="26.6",
                  match_kind="fixed-version")
        a.risks.append(RiskAssessment(match=m, score=sc, tier=tier))
    a.stats = {"macsec_score": {"score": score_val, "grade": "B"},
               "total_matches": len(a.risks)}
    return a


def test_history_record_and_diff(cfg):
    # HistoryStore defaults to MACSEC_CACHE_DIR/history.db (set by the fixture)
    store = HistoryStore()

    ctx = OrchestrationContext(config=cfg)
    ctx.inventory = _inv()
    ctx.analysis = _analysis_with(
        [("CVE-2026-86950", "macOS", "P1-CRITICAL", 10.0, True),
         ("CVE-2026-65414", "macOS", "P1-CRITICAL", 9.8, False)],
        score_val=72.0)
    id1 = store.record_scan(ctx)

    ctx.analysis = _analysis_with(
        [("CVE-2026-65414", "macOS", "P1-CRITICAL", 10.0, True)],  # now exploited
        score_val=85.0)
    id2 = store.record_scan(ctx)

    scans = store.list_scans()
    assert [s["id"] for s in scans][:2] == [id2, id1]

    d = store.diff(id1, id2)
    assert [f["cve_id"] for f in d["resolved_findings"]] == ["CVE-2026-86950"]
    assert d["new_findings"] == []
    assert [f["cve_id"] for f in d["newly_exploited"]] == ["CVE-2026-65414"]
    assert d["score_delta"] == pytest.approx(13.0)
    assert d["grade_new"] == "B"


# ------------------------------------------------------------- 3. MacSec Score

def test_score_penalizes_exploited_and_hardening():
    a = _analysis_with([("CVE-2026-86950", "macOS", "P1-CRITICAL", 10.0, True)])
    a.hardening = [
        HardeningCheck(check_id="X1", title="FileVault", category="encryption",
                       severity="high", status="fail"),
        HardeningCheck(check_id="MACSEC-UPD-002", title="OS current",
                       category="updates", severity="high", status="fail"),
    ]
    result = compute_score(a, _inv())
    # vuln: 8 (tier) + 12 (exploited) = 20
    # hardening: 8 (X1 high fail) + 8 (UPD-002 high fail) + 15 (OS outdated) = 31
    assert result["score"] == pytest.approx(49.0)
    assert result["grade"] == "D"
    assert len(result["breakdown"]) == 2


def test_score_clean_host_is_grade_a():
    a = _analysis_with([], score_val=100.0)
    a.hardening = [HardeningCheck(check_id="X1", title="SIP", category="system",
                                  severity="high", status="pass")]
    result = compute_score(a, _inv())
    assert result["score"] == 100.0
    assert result["grade"] == "A"


# ------------------------------------------------------------- 4. unsigned apps

def test_unsigned_app_check_skips_non_macos():
    ctx = OrchestrationContext(config=Config(offline=True))
    inv = _inv()
    inv.is_macos = False
    ctx.inventory = inv
    checks = HardeningAgent(ctx).run()
    app_check = next(c for c in checks if c.check_id == "MACSEC-APP-001")
    assert app_check.status == "skipped"
    assert len(checks) == 9   # 7 posture + OS currency + app audit


# ------------------------------------------------------------- 5. SARIF

def test_sarif_structure():
    a = _analysis_with([("CVE-2026-86950", "macOS", "P1-CRITICAL", 10.0, True)])
    doc = build_sarif(a, "Mac mini Apple M2")
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "macsec-agents"
    assert len(run["tool"]["driver"]["rules"]) == 4
    result = run["results"][0]
    assert result["ruleId"] == "macsec/P1-CRITICAL"
    assert result["level"] == "error"
    assert result["partialFingerprints"]["cve"] == "CVE-2026-86950"
    assert "Mac mini Apple M2" in result["message"]["text"]
