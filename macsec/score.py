"""MacSec Score: a single 0-100 composite security grade for the machine.

Combines patch exposure (matched CVEs by tier and exploitation status),
hardening posture (control failures weighted by severity) and OS currency.
Intended as the headline metric in reports and for tracking trend via
`macsec history` / `macsec diff`.
"""

from __future__ import annotations

from macsec.models import AnalysisResult, Inventory

TIER_PENALTY = {"P1-CRITICAL": 8.0, "P2-HIGH": 3.0, "P3-MEDIUM": 1.0, "P4-LOW": 0.25}
EXPLOITED_PENALTY = 12.0            # on top of the tier penalty
SEVERITY_PENALTY = {"high": 8.0, "medium": 4.0, "low": 1.5}
OS_OUTDATED_PENALTY = 15.0
CAP_PER_CATEGORY = 60.0             # no single category can sink the score alone


def compute_score(analysis: AnalysisResult, inv: Inventory | None) -> dict:
    breakdown: list[dict] = []

    # --- vulnerability exposure
    vuln_pen = 0.0
    exploited_n = 0
    for r in analysis.risks:
        vuln_pen += TIER_PENALTY.get(r.tier, 0)
        if r.match.cve.exploited:
            vuln_pen += EXPLOITED_PENALTY
            exploited_n += 1
    vuln_pen = min(vuln_pen, CAP_PER_CATEGORY)
    breakdown.append({"category": "vulnerability exposure",
                      "penalty": round(vuln_pen, 1),
                      "detail": f"{len(analysis.risks)} matched CVEs, {exploited_n} exploited"})

    # --- hardening posture
    hard_pen = 0.0
    failed = [c for c in analysis.hardening if c.status == "fail"]
    for c in failed:
        hard_pen += SEVERITY_PENALTY.get(c.severity, 2.0)
    os_currency = next((c for c in analysis.hardening if c.check_id == "MACSEC-UPD-002"), None)
    if os_currency is not None and os_currency.status == "fail":
        hard_pen += OS_OUTDATED_PENALTY
    hard_pen = min(hard_pen, CAP_PER_CATEGORY)
    breakdown.append({"category": "hardening posture",
                      "penalty": round(hard_pen, 1),
                      "detail": f"{len(failed)} controls failing"})

    score = max(0.0, round(100.0 - vuln_pen - hard_pen, 1))
    grade = ("A" if score >= 90 else "B" if score >= 75 else
             "C" if score >= 60 else "D" if score >= 40 else "F")
    return {"score": score, "grade": grade, "breakdown": breakdown,
            "host": f"{inv.model} {inv.chip}".strip() if inv else ""}
