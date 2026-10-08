"""EPSSAgent: enriches matched CVEs with FIRST.org Exploit Prediction Scoring.

EPSS gives each CVE a probability (0-1) of being exploited in the wild in the
next 30 days, plus a percentile rank. The analyzer fuses this into the
composite score so "likely to be exploited soon" findings surface even when
they are not yet in CISA KEV.
"""

from __future__ import annotations

import json

from macsec.agents.base import Agent
from macsec.utils import http_get


class EPSSAgent(Agent):
    name = "epss-enricher"
    role = "threat-intel"
    description = "Adds FIRST.org EPSS exploit-probability scores to matched CVEs"

    def run(self) -> int:
        matches = self.ctx.analysis.matches
        if not matches:
            self.log("no matches to enrich")
            return 0

        cve_ids = sorted({m.cve.cve_id for m in matches})
        scores: dict[str, dict] = {}
        batch = self.cfg.epss_batch
        for i in range(0, len(cve_ids), batch):
            chunk = cve_ids[i:i + batch]
            url = f"{self.cfg.epss_url}?cve={','.join(chunk)}"
            try:
                raw = http_get(url, ttl=self.cfg.feed_ttl, offline=self.cfg.offline,
                               timeout=60)
                data = json.loads(raw)
            except (RuntimeError, json.JSONDecodeError) as exc:
                self.log(f"EPSS batch failed ({exc}); continuing without it", "warn")
                continue
            for row in data.get("data", []):
                try:
                    scores[row["cve"]] = {
                        "epss": float(row.get("epss", 0)),
                        "epss_percentile": float(row.get("percentile", 0)),
                    }
                except (KeyError, ValueError):
                    continue

        enriched = 0
        for m in matches:
            s = scores.get(m.cve.cve_id)
            if s:
                m.cve.extra.update(s)
                enriched += 1
        self.ctx.analysis.stats["epss_enriched"] = enriched
        hi = sum(1 for s in scores.values() if s["epss"] >= 0.5)
        self.log(f"{enriched}/{len(cve_ids)} CVEs enriched, {hi} with >=50% exploit probability")
        return enriched
