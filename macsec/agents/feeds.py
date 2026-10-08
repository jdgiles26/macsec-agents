"""Feed agents: pull vulnerability intelligence from public sources.

Agents:
  - AppleCVEWebsiteAgent : theevilbit/apple-cve-website db.json (full Apple CVE set,
                           parsed from Apple's own security releases pages, includes
                           "may have been exploited" flags and CVSS from NVD)
  - KEVAgent             : CISA Known Exploited Vulnerabilities catalog
  - AppleReleasesAgent   : support.apple.com/en-us/100100 (latest Apple security releases)
  - NVDAgent             : NVD API 2.0 keyword lookups for installed third-party software
"""

from __future__ import annotations

import json
import re
import time
from html.parser import HTMLParser

import requests

from macsec.agents.base import Agent
from macsec.models import CVERecord, FeedResult, utcnow
from macsec.utils import http_get, severity_of


# ============================================================ apple-cve-website

def _record_from_api(cve: dict) -> CVERecord:
    """Normalize one record of the v2 per-year API (api/cves-YYYY.json)."""
    fixes = cve.get("fixes") or []
    latest = fixes[-1] if fixes else {}
    research = cve.get("research") or []
    campaigns = [c.get("name", "") for c in cve.get("campaigns") or [] if c.get("name")]
    refs = [r.get("url", "") for r in research if r.get("url")][:5]
    extra: dict = {
        "has_poc": any(r.get("kind") == "poc" for r in research),
        "research_links": len(research),
    }
    if campaigns:
        extra["campaigns"] = campaigns
    if cve.get("contest"):
        extra["contest"] = cve["contest"]
    return CVERecord(
        cve_id=cve.get("cve", ""),
        source="apple-cve-website",
        description=latest.get("impact") or latest.get("description") or "",
        component=latest.get("component", ""),
        impact=latest.get("impact", ""),
        cvss=cve.get("cvss") or None,
        severity=severity_of(cve.get("cvss")),
        exploited=bool(cve.get("exploited")),
        date_published=cve.get("first_fixed") or latest.get("date", ""),
        advisory_title=latest.get("advisory", ""),
        advisory_url=latest.get("url") or cve.get("url", ""),
        platforms=list(cve.get("platforms") or []),
        fixed_versions=[f.get("advisory", "") for f in fixes if f.get("advisory")],
        affected_product=latest.get("available_for", ""),
        references=refs,
        extra=extra,
    )


class AppleCVEWebsiteAgent(Agent):
    """Decode the Apple CVE dataset from theevilbit/apple-cve-website.

    Primary path is the v2 API: api/index.json -> per-year api/cves-YYYY.json
    files (decompressed JSON: cvss, exploited flag, fixes with advisory names,
    research links, exploit campaigns). If the index cannot be fetched, falls
    back to the legacy monolithic data/db.json (compressed schema v1).

    Legacy schema (v1, index-compressed arrays):
      platforms:   [name, ...]
      advisories:  [[title, date, url, [platformIdx], [versionLabels], product,
                     nocveFlag, entryCount, approxFlag,
                     [[platformIdx, major, "v1,v2,..."]], archivedFlag], ...]
      entries:     [[advisoryIdx, componentIdx, impactIdx, descriptionIdx,
                     exploitedFlag, impactClassIdx, [[cveIdx, creditIdx], ...],
                     availableForIdx, ?, ?, addedDate], ...]
      cves/components/impacts/impactClasses/descriptions/availableFor: string tables
      cvss:        per-CVE base score (float or null), sourced from NVD
    """

    name = "apple-cve-db"
    role = "threat-intel"
    description = "Decodes the theevilbit/apple-cve-website Apple CVE database"

    def run(self) -> FeedResult:
        result = FeedResult(source="apple-cve-website", fetched_at=utcnow())
        try:
            index = json.loads(self._fetch(self.cfg.apple_cve_index_url))
            result.records, result.meta = self._decode_v2(index)
        except (RuntimeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            self.log(f"API index unavailable ({exc}); trying legacy db.json", "warn")
            raw = self._fetch(self.cfg.apple_cve_db_url)
            db = json.loads(raw)
            result.records, result.meta = self._decode_v1(db)

        exploited = sum(1 for r in result.records if r.exploited)
        pocs = sum(1 for r in result.records if r.extra.get("has_poc"))
        self.log(f"{len(result.records)} unique Apple CVEs "
                 f"({exploited} exploited, {pocs} with public PoC)")
        self.ctx.feeds.append(result)
        return result

    # ------------------------------------------------------------ fetching

    def _fetch(self, url: str) -> bytes:
        """Fetch with CDN mirror fallback (raw.githubusercontent -> jsDelivr).

        Once the primary host fails, the mirror is preferred for the rest of
        the run so we don't pay the retry/backoff cost on every file.
        """
        from macsec.utils import mirror_urls
        candidates = [url, *mirror_urls(url)]
        if getattr(self, "_mirror_preferred", False) and len(candidates) > 1:
            candidates = candidates[1:] + candidates[:1]
        last_err: Exception | None = None
        for i, candidate in enumerate(candidates):
            try:
                data = http_get(candidate, ttl=self.cfg.feed_ttl,
                                offline=self.cfg.offline)
                if i > 0:
                    self._mirror_preferred = True
                return data
            except RuntimeError as exc:
                last_err = exc
                self.log(f"fetch failed: {candidate} ({exc})", "warn")
                self._mirror_preferred = True
        raise RuntimeError(f"all mirrors failed for {url}: {last_err}")

    # ------------------------------------------------------------ v2 API

    def _decode_v2(self, index: dict) -> tuple[list[CVERecord], dict]:
        from concurrent.futures import ThreadPoolExecutor
        files = index.get("files") or {}
        years = sorted(files.keys(), reverse=True)
        if self.cfg.apple_cve_years > 0:
            years = years[: self.cfg.apple_cve_years]
        base = self.cfg.apple_cve_index_url.rsplit("/", 1)[0].rsplit("/", 1)[0]

        def load(year: str) -> list:
            raw = self._fetch(f"{base}/{files[year]}")
            return json.loads(raw)

        records: list[CVERecord] = []
        errors: list[str] = []
        with ThreadPoolExecutor(max_workers=4) as pool:
            future_map = {pool.submit(load, y): y for y in years}
            for fut, year in future_map.items():
                try:
                    records.extend(_record_from_api(c) for c in fut.result())
                except Exception as exc:
                    errors.append(f"year {year}: {exc}")
                    self.log(f"year {year} failed: {exc}", "warn")
        if errors:
            self.ctx.log(self.name, "; ".join(errors), "error")
        meta = {"api": "v2", "years": years, "count": index.get("count"),
                "year_errors": errors}
        return records, meta

    # ------------------------------------------------------------ legacy v1

    def _decode_v1(self, db: dict) -> tuple[list[CVERecord], dict]:

        platforms = db["platforms"]
        advisories = db["advisories"]
        cves = db["cves"]
        comps = db["components"]
        impacts = db["impacts"]
        classes = db["impactClasses"]
        descs = db["descriptions"]
        avail = db["availableFor"]
        cvss = db.get("cvss") or []

        # aggregate per CVE across all advisories it appears in
        agg: dict[int, CVERecord] = {}
        for entry in db["entries"]:
            adv = advisories[entry[0]]
            title, date, url = adv[0], adv[1] or "", adv[2]
            plat_names = [platforms[i] for i in adv[3] if 0 <= i < len(platforms)]
            version_labels = list(adv[4] or [])
            fixed = []
            for _p, major, vs in adv[9] or []:
                for v in (vs or "").split(","):
                    v = v.strip()
                    if v:
                        fixed.append(f"{adv[5]} {v}".strip())
            exploited = bool(entry[4])
            comp = comps[entry[1]] if 0 <= entry[1] < len(comps) else ""
            impact = impacts[entry[2]] if 0 <= entry[2] < len(impacts) else ""
            desc = descs[entry[3]] if 0 <= entry[3] < len(descs) else ""
            iclass = classes[entry[5]] if 0 <= entry[5] < len(classes) else ""
            avail_for = avail[entry[7]] if 0 <= entry[7] < len(avail) else ""

            for cve_idx, _credit in entry[6]:
                rec = agg.get(cve_idx)
                if rec is None:
                    score = cvss[cve_idx] if cve_idx < len(cvss) else None
                    rec = CVERecord(
                        cve_id=cves[cve_idx],
                        source="apple-cve-website",
                        description=impact or desc,
                        component=comp,
                        impact=impact,
                        impact_class=iclass,
                        cvss=score or None,
                        severity=severity_of(score),
                        exploited=exploited,
                        date_published=date,
                        advisory_title=title,
                        advisory_url=url,
                        platforms=[],
                        fixed_versions=[],
                        affected_product=adv[5] or "",
                        extra={"available_for": avail_for} if avail_for else {},
                    )
                    agg[cve_idx] = rec
                rec.exploited = rec.exploited or exploited
                for p in plat_names:
                    if p not in rec.platforms:
                        rec.platforms.append(p)
                for v in fixed + version_labels:
                    if v and v not in rec.fixed_versions:
                        rec.fixed_versions.append(v)
                if date and (not rec.date_published or date > rec.date_published):
                    rec.date_published, rec.advisory_title, rec.advisory_url = date, title, url

        meta = dict(db.get("meta", {}))
        meta["api"] = "v1-legacy"
        return list(agg.values()), meta


# ============================================================ CISA KEV

class KEVAgent(Agent):
    name = "cisa-kev"
    role = "threat-intel"
    description = "Flags CVEs present in the CISA Known Exploited Vulnerabilities catalog"

    def run(self) -> FeedResult:
        result = FeedResult(source="cisa-kev", fetched_at=utcnow())
        raw = http_get(self.cfg.cisa_kev_url, ttl=self.cfg.feed_ttl,
                       offline=self.cfg.offline)
        data = json.loads(raw)
        result.meta = {"count": data.get("count"), "dateReleased": data.get("dateReleased")}
        for v in data.get("vulnerabilities", []):
            rec = CVERecord(
                cve_id=v.get("cveID", ""),
                source="cisa-kev",
                description=v.get("shortDescription", ""),
                exploited=True,
                date_published=v.get("dateAdded", ""),
                affected_product=f"{v.get('vendorProject', '')} {v.get('product', '')}".strip(),
                component=v.get("vulnerabilityName", ""),
                extra={"required_action": v.get("requiredAction", ""),
                       "due_date": v.get("dueDate", ""),
                       "known_ransomware": v.get("knownRansomwareCampaignUse", "")},
            )
            result.records.append(rec)
        self.log(f"{len(result.records)} KEV entries")
        self.ctx.feeds.append(result)
        return result


# ============================================================ Apple security releases

class _ReleasePageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.rows: list[dict] = []
        self._cell_text: list[str] = []
        self._in_cell = False
        self._row: list[str] = []
        self._link = ""
        self._in_link = False

    def handle_starttag(self, tag, attrs):
        if tag in ("td", "th"):
            self._in_cell, self._cell_text = True, []
        elif tag == "a" and self._in_cell:
            href = dict(attrs).get("href", "")
            if "support.apple.com" in href or href.startswith("/"):
                self._link = href

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self._in_cell:
            self._row.append(" ".join("".join(self._cell_text).split()))
            self._in_cell = False
        elif tag == "tr" and self._row:
            self.rows.append({"cells": self._row, "link": self._link})
            self._row, self._link = [], ""

    def handle_data(self, data):
        if self._in_cell:
            self._cell_text.append(data)


class AppleReleasesAgent(Agent):
    """Parse Apple's security releases page (HT100100) for the latest macOS updates."""

    name = "apple-releases"
    role = "threat-intel"
    description = "Tracks the latest Apple security releases for macOS"

    MACOS_ROW_RE = re.compile(r"^macOS\s+\w+\s+([\d.]+)", re.IGNORECASE)

    def run(self) -> FeedResult:
        result = FeedResult(source="apple-releases", fetched_at=utcnow())
        raw = http_get(self.cfg.apple_releases_url, ttl=self.cfg.feed_ttl,
                       offline=self.cfg.offline)
        parser = _ReleasePageParser()
        parser.feed(raw.decode("utf-8", "replace"))
        releases: list[dict] = []
        for row in parser.rows:
            cells = row["cells"]
            if len(cells) < 2:
                continue
            m = self.MACOS_ROW_RE.match(cells[0])
            if not m:
                continue
            releases.append({
                "name": cells[0],
                "version": m.group(1),
                "date": cells[1] if len(cells) > 1 else "",
                "url": row["link"],
            })
        result.meta["macos_releases"] = releases
        if releases:
            latest = max(r["version"] for r in releases)  # lexical OK for display only
            self.log(f"{len(releases)} macOS releases tracked, newest listing: {latest}")
        else:
            result.errors.append("no macOS rows parsed from Apple releases page")
            self.log("no macOS rows parsed (page layout may have changed)", "warn")
        self.ctx.feeds.append(result)
        return result


# ============================================================ NVD

class NVDAgent(Agent):
    """Query the NVD API for CVEs against installed third-party software."""

    name = "nvd-lookup"
    role = "threat-intel"
    description = "Queries NVD for CVEs affecting installed third-party software"

    # products we never query (OS components / noise)
    SKIP_PREFIXES = ("com.apple.", "python", "pip", "setuptools", "wheel")

    def run(self) -> FeedResult:
        result = FeedResult(source="nvd", fetched_at=utcnow())
        inv = self.ctx.inventory
        if inv is None or not inv.software:
            result.errors.append("no software inventory to query")
            self.ctx.feeds.append(result)
            return result

        names = self._candidate_products(inv.software)
        names = names[: self.cfg.nvd_max_products]
        delay = 0.8 if self.cfg.nvd_api_key else 6.5
        self.log(f"querying NVD for {len(names)} products "
                 f"({'API key' if self.cfg.nvd_api_key else 'no key, throttled'})")

        headers = {"apiKey": self.cfg.nvd_api_key} if self.cfg.nvd_api_key else {}
        for i, item in enumerate(names):
            try:
                self._query_product(item["name"], item["version"], result, headers)
            except requests.RequestException as exc:
                result.errors.append(f"{item['name']}: {exc}")
            if i < len(names) - 1:
                time.sleep(delay)
        self.log(f"{len(result.records)} NVD CVEs for installed software")
        self.ctx.feeds.append(result)
        return result

    def _candidate_products(self, software) -> list[dict]:
        out, seen = [], set()
        # GUI apps and brew packages first: most attack surface
        order = {"brew-cask": 0, "brew": 1, "system_profiler": 2, "pip": 3}
        for item in sorted(software, key=lambda s: order.get(s.source, 9)):
            n = item.name.lower().strip()
            if not n or n in seen or any(n.startswith(p) for p in self.SKIP_PREFIXES):
                continue
            seen.add(n)
            out.append({"name": item.name, "version": item.version})
        return out

    def _query_product(self, name: str, version: str, result: FeedResult,
                       headers: dict) -> None:
        resp = requests.get(
            self.cfg.nvd_api_url,
            params={"keywordSearch": name, "resultsPerPage": 20},
            headers={"User-Agent": "macsec-agents/1.0", **headers},
            timeout=60,
        )
        if resp.status_code == 429:
            time.sleep(30)
            resp.raise_for_status()
        resp.raise_for_status()
        for vuln in resp.json().get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            desc = next((d["value"] for d in cve.get("descriptions", [])
                         if d.get("lang") == "en"), "")
            # keep only hits that plausibly name the product
            if name.lower() not in desc.lower() and name.lower() not in json.dumps(
                    cve.get("configurations", [])).lower():
                continue
            score = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = cve.get("metrics", {}).get(key)
                if metrics:
                    score = metrics[0].get("cvssData", {}).get("baseScore")
                    break
            refs = [r.get("url", "") for r in cve.get("references", [])][:5]
            result.records.append(CVERecord(
                cve_id=cve_id, source="nvd", description=desc,
                cvss=score, severity=severity_of(score),
                date_published=(cve.get("published") or "")[:10],
                affected_product=name, references=refs,
                extra={"installed_version": version},
            ))
