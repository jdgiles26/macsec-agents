"""SARIF 2.1.0 export: feed macsec findings into GitHub Code Scanning / CI gates."""

from __future__ import annotations

from macsec.models import AnalysisResult

TIER_LEVEL = {"P1-CRITICAL": "error", "P2-HIGH": "error",
              "P3-MEDIUM": "warning", "P4-LOW": "note"}


def build_sarif(analysis: AnalysisResult, host: str = "") -> dict:
    """Convert risk assessments into a SARIF 2.1.0 log."""
    rules = [
        {
            "id": f"macsec/{tier}",
            "name": tier.replace("-", ""),
            "shortDescription": {"text": f"{tier} vulnerability exposure on this Mac"},
            "fullDescription": {
                "text": f"A CVE matched this host at priority {tier}. "
                        "Scoring combines CVSS, active-exploitation intelligence "
                        "(Apple / CISA KEV) and EPSS exploit probability."},
            "defaultConfiguration": {"level": level},
            "properties": {"security-severity": str({"P1-CRITICAL": 9.0, "P2-HIGH": 7.0,
                                                     "P3-MEDIUM": 5.0, "P4-LOW": 2.0}[tier])},
        }
        for tier, level in TIER_LEVEL.items()
    ]

    results = []
    for r in analysis.risks:
        cve = r.match.cve
        props = {"cvss": cve.cvss, "compositeScore": r.score,
                 "exploited": cve.exploited, "confidence": r.match.confidence,
                 "matchKind": r.match.match_kind, "factors": r.factors}
        if cve.extra.get("epss") is not None:
            props["epss"] = cve.extra["epss"]
            props["epssPercentile"] = cve.extra.get("epss_percentile")
        results.append({
            "ruleId": f"macsec/{r.tier}",
            "level": TIER_LEVEL.get(r.tier, "note"),
            "message": {"text": f"{cve.cve_id} affects {r.match.target} "
                                f"{r.match.target_version} on {host or 'this host'}. "
                                f"{r.recommendation}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"host://{r.match.target}"},
                },
                "logicalLocations": [{"name": r.match.target,
                                      "fullyQualifiedName": f"{r.match.target} {r.match.target_version}".strip()}],
            }],
            "partialFingerprints": {"cve": cve.cve_id, "target": r.match.target},
            "properties": props,
            "helpUri": cve.advisory_url or
                       f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "macsec-agents",
                    "informationUri": "https://github.com/theevilbit/apple-cve-website",
                    "version": "1.1.0",
                    "rules": rules,
                }
            },
            "results": results,
            "properties": {"host": host, "stats": analysis.stats},
        }],
    }
