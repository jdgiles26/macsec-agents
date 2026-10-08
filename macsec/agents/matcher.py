"""Matcher and risk analyzer agents.

MatcherAgent  : correlates feed CVEs with the host inventory.
AnalyzerAgent : scores and tiers every match, then writes recommendations.
"""

from __future__ import annotations

import re

from macsec.agents.base import Agent
from macsec.models import CVERecord, Match, RiskAssessment
from macsec.utils import parse_version


class MatcherAgent(Agent):
    name = "cve-matcher"
    role = "correlation"
    description = "Correlates Apple/KEV/NVD CVEs with this Mac's OS version and software"

    def run(self) -> list[Match]:
        inv = self.ctx.inventory
        if inv is None:
            self.log("no inventory in context, nothing to match", "warn")
            return []

        apple: dict[str, CVERecord] = {}
        kev_ids: set[str] = set()
        nvd: list[CVERecord] = []
        for feed in self.ctx.feeds:
            if feed.source == "apple-cve-website":
                for r in feed.records:
                    apple[r.cve_id] = r
            elif feed.source == "cisa-kev":
                kev_ids = {r.cve_id for r in feed.records}
            elif feed.source == "nvd":
                nvd.extend(feed.records)

        matches: list[Match] = []
        if inv.is_macos and inv.macos_product_version:
            matches += self._match_macos(inv, apple, kev_ids)
        matches += self._match_software(inv, nvd, apple, kev_ids)

        self.ctx.analysis.matches = matches
        p1 = sum(1 for m in matches if m.cve.exploited)
        self.log(f"{len(matches)} matches ({p1} actively exploited)")
        return matches

    # ------------------------------------------------------------ macOS

    def _match_macos(self, inv, apple: dict[str, CVERecord],
                     kev_ids: set[str]) -> list[Match]:
        """A CVE applies when it was fixed in a macOS release newer than ours,
        or our version predates the advisory's fixed-version labels."""
        out: list[Match] = []
        current = inv.macos_product_version
        for rec in apple.values():
            if "macOS" not in rec.platforms and "OS X" not in rec.platforms:
                continue
            verdict = self._os_affected(current, inv.macos_major, rec)
            if verdict is None:
                continue
            kind, confidence, rationale = verdict
            if rec.cve_id in kev_ids:
                rec.exploited = True
            out.append(Match(cve=rec, target="macOS", target_version=current,
                             match_kind=kind, confidence=confidence, rationale=rationale))
        return out

    def _os_affected(self, current: str, current_major: int, rec: CVERecord):
        """Heuristic: parse macOS x.y(.z) labels out of fixed_versions/advisory title."""
        fixed_versions: list[str] = []
        majors_touched: set[int] = set()
        for label in rec.fixed_versions + [rec.advisory_title, rec.affected_product]:
            for m in re.finditer(r"macOS\s+(?:[A-Za-z]+\s+)?(\d+)(?:\.(\d+))?(?:\.(\d+))?", label or ""):
                major = int(m.group(1))
                full = ".".join(g for g in m.groups() if g is not None)
                majors_touched.add(major)
                fixed_versions.append(full)
        if not majors_touched:
            # macOS platform CVE with no version info: treat as potential match
            return ("kev-flag" if rec.exploited else "platform", "low",
                    "macOS platform CVE, no fixed-version data in feed")

        # our major wasn't covered by the advisory at all
        if current_major and current_major > max(majors_touched):
            return None
        if current_major and current_major < min(majors_touched):
            return None  # older branch, advisory doesn't cover it (heuristic)

        cur_v = parse_version(current)
        # A CVE can be listed under several advisories for the same macOS major
        # (e.g. fixed in 26.6, re-listed in 26.7): the EARLIEST fix release is
        # what matters — running at or beyond it means we are patched.
        # Major-only labels like "macOS 26 Tahoe" name the branch, not a fix
        # release, so prefer precise x.y(.z) versions when available.
        same_major = [v for v in fixed_versions
                      if parse_version(v) and int(str(parse_version(v)).split('.')[0]) == current_major]
        precise = [v for v in same_major if "." in v] or same_major
        first_fixed = min((parse_version(v) for v in precise), default=None)
        if first_fixed is None:
            return ("os-version", "low", "advisory touches this macOS major but no version list")
        if cur_v is not None and cur_v < first_fixed:
            return ("fixed-version", "high",
                    f"running {current}, fixed in {first_fixed}")
        return None  # we're patched at or beyond the first fixed version

    # ------------------------------------------------------------ software

    def _match_software(self, inv, nvd: list[CVERecord],
                        apple: dict[str, CVERecord], kev_ids: set[str]) -> list[Match]:
        out: list[Match] = []
        names = {s.name.lower(): s for s in inv.software}

        # NVD records already carry affected_product from our own queries
        seen: set[tuple[str, str]] = set()
        for rec in nvd:
            key = (rec.cve_id, rec.affected_product.lower())
            if key in seen:
                continue
            seen.add(key)
            item = names.get(rec.affected_product.lower())
            out.append(Match(
                cve=rec, target=rec.affected_product,
                target_version=(item.version if item else rec.extra.get("installed_version", "")),
                match_kind="keyword", confidence="medium",
                rationale="NVD keyword match against installed product name",
            ))

        # KEV entries that name an installed product
        for feed in self.ctx.feeds:
            if feed.source != "cisa-kev":
                continue
            for rec in feed.records:
                prod = rec.affected_product.lower()
                for name, item in names.items():
                    if len(name) >= 4 and name in prod:
                        apple_rec = apple.get(rec.cve_id)
                        use = apple_rec if apple_rec else rec
                        use.exploited = True
                        out.append(Match(
                            cve=use, target=item.name, target_version=item.version,
                            match_kind="kev-flag", confidence="medium",
                            rationale="product appears in CISA KEV (actively exploited)",
                        ))
                        break
        return out


class AnalyzerAgent(Agent):
    name = "risk-analyzer"
    role = "analysis"
    description = "Scores matched CVEs (CVSS x exploitation x exposure) into priority tiers"

    def run(self) -> list[RiskAssessment]:
        risks: list[RiskAssessment] = []
        for m in self.ctx.analysis.matches:
            risks.append(self._score(m))
        tier_rank = {"P1-CRITICAL": 0, "P2-HIGH": 1, "P3-MEDIUM": 2, "P4-LOW": 3}
        risks.sort(key=lambda r: (tier_rank.get(r.tier, 4), -r.score))
        self.ctx.analysis.risks = risks

        stats = self.ctx.analysis.stats
        stats["total_matches"] = len(risks)
        stats["by_tier"] = {t: sum(1 for r in risks if r.tier == t) for t in tier_rank}
        stats["exploited"] = sum(1 for r in risks if r.match.cve.exploited)
        if risks:
            self.log(f"tiered {len(risks)} findings: "
                     + ", ".join(f"{t}={stats['by_tier'][t]}" for t in tier_rank))
        return risks

    def _score(self, m: Match) -> RiskAssessment:
        score = m.cve.cvss or 5.0
        factors = [f"base {score:.1f}"]

        if m.cve.exploited:
            score = min(10.0, score + 2.0)
            factors.append("actively exploited (+2.0)")
        if m.match_kind == "fixed-version":
            score = min(10.0, score + 0.5)
            factors.append("confirmed unpatched OS version (+0.5)")
        if m.confidence == "low":
            score = max(1.0, score - 1.0)
            factors.append("low-confidence match (-1.0)")
        ic = (m.cve.impact_class or "").lower()
        if any(k in ic for k in ("execute arbitrary code", "kernel privileges", "rce")):
            score = min(10.0, score + 0.5)
            factors.append("code-execution impact (+0.5)")
        epss = m.cve.extra.get("epss")
        if epss is not None:
            if epss >= 0.5:
                score = min(10.0, score + 1.0)
                factors.append(f"EPSS {epss:.0%} exploit probability (+1.0)")
            elif epss >= 0.1:
                score = min(10.0, score + 0.5)
                factors.append(f"EPSS {epss:.0%} exploit probability (+0.5)")
        if m.cve.extra.get("has_poc"):
            score = min(10.0, score + 0.5)
            factors.append("public PoC available (+0.5)")
        if m.cve.extra.get("campaigns"):
            score = min(10.0, score + 0.5)
            factors.append("named exploit campaign: "
                           + ", ".join(m.cve.extra["campaigns"]) + " (+0.5)")

        if score >= 9 or (m.cve.exploited and score >= 7):
            tier = "P1-CRITICAL"
        elif score >= 7:
            tier = "P2-HIGH"
        elif score >= 4:
            tier = "P3-MEDIUM"
        else:
            tier = "P4-LOW"

        if m.target == "macOS":
            rec = (f"Update macOS to the release that fixes {m.cve.cve_id} "
                   f"(System Settings -> General -> Software Update). {m.rationale}")
        else:
            rec = (f"Update or remove {m.target} (installed {m.target_version or 'unknown'}). "
                   f"{m.rationale}")
        return RiskAssessment(match=m, score=round(score, 1), tier=tier,
                              factors=factors, recommendation=rec)
