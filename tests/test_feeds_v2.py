"""Tests for the v2 apple-cve-website API decoder and mirror fallback."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from macsec.agents.base import OrchestrationContext
from macsec.agents.feeds import AppleCVEWebsiteAgent
from macsec.agents.matcher import MatcherAgent
from macsec.config import Config
from macsec.models import Inventory

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def cfg(tmp_path, monkeypatch) -> Config:
    monkeypatch.setenv("MACSEC_CACHE_DIR", str(tmp_path / "cache"))
    c = Config()
    c.offline = True
    return c


def _seed(cfg: Config, url: str, fixture: str) -> None:
    from macsec.utils import cache_dir
    import hashlib
    key = hashlib.sha256(url.encode()).hexdigest()[:32]
    (cache_dir() / f"{key}.bin").write_bytes((FIXTURES / fixture).read_bytes())
    (cache_dir() / f"{key}.meta.json").write_text(json.dumps({"ts": time.time()}))


def test_v2_api_decoder(cfg):
    _seed(cfg, cfg.apple_cve_index_url, "apple_api_index_sample.json")
    base = cfg.apple_cve_index_url.rsplit("/", 1)[0].rsplit("/", 1)[0]
    _seed(cfg, f"{base}/api/cves-2026.json", "apple_api_2026_sample.json")

    ctx = OrchestrationContext(config=cfg)
    feed = AppleCVEWebsiteAgent(ctx).timed_run()
    assert feed.meta["api"] == "v2"
    by_id = {r.cve_id: r for r in feed.records}
    assert len(by_id) == 8

    exploited = by_id["CVE-2026-20700"]
    assert exploited.exploited is True
    assert exploited.cvss == 7.8
    assert exploited.extra["has_poc"] is True
    assert exploited.extra["campaigns"] == ["DarkSword"]
    assert "macOS" in exploited.platforms
    assert "macOS Tahoe 26.3" in exploited.fixed_versions

    c = by_id["CVE-2026-86950"]
    assert c.component == "" or isinstance(c.component, str)
    assert "macOS Tahoe 26.7.1" in c.fixed_versions


def test_v2_matching_against_macos(cfg):
    _seed(cfg, cfg.apple_cve_index_url, "apple_api_index_sample.json")
    base = cfg.apple_cve_index_url.rsplit("/", 1)[0].rsplit("/", 1)[0]
    _seed(cfg, f"{base}/api/cves-2026.json", "apple_api_2026_sample.json")

    ctx = OrchestrationContext(config=cfg)
    ctx.inventory = Inventory.from_dict(
        json.loads((FIXTURES / "inventory_macmini_m2.json").read_text()))
    AppleCVEWebsiteAgent(ctx).run()
    matches = MatcherAgent(ctx).run()
    ids = {m.cve.cve_id for m in matches}
    # fixed in Tahoe 26.7/26.7.1, host runs 26.6 -> affected
    assert "CVE-2026-86950" in ids and "CVE-2026-20683" in ids
    # CVE-2026-28899 was already fixed in Tahoe 26.6 -> not affected
    assert "CVE-2026-28899" not in ids
    m = next(m for m in matches if m.cve.cve_id == "CVE-2026-86950")
    assert m.match_kind == "fixed-version" and m.confidence == "high"


def test_legacy_v1_fallback_when_index_missing(cfg):
    """Offline + no cached index -> falls back to cached legacy db.json."""
    _seed(cfg, cfg.apple_cve_db_url, "apple_db_sample.json")
    ctx = OrchestrationContext(config=cfg)
    feed = AppleCVEWebsiteAgent(ctx).timed_run()
    assert feed.meta.get("api") == "v1-legacy"
    by_id = {r.cve_id: r for r in feed.records}
    assert "CVE-2026-86950" in by_id
    assert by_id["CVE-2026-86950"].exploited is True


def test_mirror_fallback(cfg, monkeypatch):
    """Primary raw.githubusercontent URL fails -> jsDelivr mirror serves the file."""
    _seed(cfg, "https://cdn.jsdelivr.net/gh/theevilbit/apple-cve-website@main/api/index.json",
          "apple_api_index_sample.json")
    _seed(cfg, "https://cdn.jsdelivr.net/gh/theevilbit/apple-cve-website@main/api/cves-2026.json",
          "apple_api_2026_sample.json")

    from macsec.utils import http_get as real_http_get
    import macsec.agents.feeds as feeds_mod

    def flaky(url, **kw):
        if "raw.githubusercontent.com" in url:
            raise RuntimeError("simulated primary outage")
        return real_http_get(url, **kw)

    monkeypatch.setattr(feeds_mod, "http_get", flaky)
    ctx = OrchestrationContext(config=cfg)
    feed = AppleCVEWebsiteAgent(ctx).timed_run()
    assert feed.meta["api"] == "v2"
    assert len(feed.records) == 8
