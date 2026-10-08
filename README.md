# macsec-agents

An agentic, open-source CLI that fields a **team of orchestrated security agents** to
review, analyze, document, harden and report on **CVEs and vulnerabilities for your
Apple silicon Mac** (Mac mini M2 and any other Apple silicon / Intel Mac).

It consumes the [theevilbit/apple-cve-website](https://github.com/theevilbit/apple-cve-website)
Apple CVE dataset — v2 per-year API (`api/cves-YYYY.json`) with jsDelivr CDN mirror
fallback and a legacy `db.json` decoder — including "may have been exploited" flags,
named exploit campaigns, public-PoC links and NVD-sourced CVSS scores. Exploitation is
cross-checked against the **CISA KEV catalog**, exploit probability comes from
**FIRST.org EPSS**, the latest releases are tracked on
[support.apple.com/en-us/100100](https://support.apple.com/en-us/100100), and the
**NVD API** covers your installed third-party software.

## The agent team

| Agent | Role | Mission |
|-------|------|---------|
| `inventory-collector` | recon | Hardware, OS build, installed software (brew/casks/pip/apps), security posture |
| `apple-cve-db` | threat-intel | Apple CVE dataset (v2 API, mirror fallback, legacy v1 decoder) |
| `cisa-kev` | threat-intel | Flags actively exploited CVEs (CISA Known Exploited Vulnerabilities) |
| `apple-releases` | threat-intel | Latest macOS security releases from Apple's HT100100 page |
| `nvd-lookup` | threat-intel | Per-product NVD API lookups for installed third-party software |
| `epss-enricher` | threat-intel | FIRST.org EPSS exploit-probability scores for every matched CVE |
| `cve-matcher` | correlation | Links CVEs to your exact macOS version and installed apps |
| `risk-analyzer` | analysis | Composite scoring (CVSS × KEV/Apple exploitation × EPSS × PoC) into P1–P4 tiers |
| `llm-analyst` | analysis | Executive summary from a **local open-source model via Ollama** (rule-based fallback) |
| `hardening-auditor` | hardening | CIS-style controls + unsigned/unnotarized app audit (spctl/codesign) |
| `scorekeeper` | analysis | MacSec Score: composite 0–100 host security grade (A–F) |
| `historian` | memory | Persists every scan to SQLite; `macsec history` / `macsec diff` show trends |
| `reporter` | documentation | JSON + Markdown + HTML + **SARIF** (GitHub Code Scanning) reports |

Agents communicate through a shared blackboard (`OrchestrationContext`); the
orchestrator runs the three fast feeds **in parallel**, sequences the rate-limited
NVD lookups, and degrades gracefully when any feed is unavailable.

## Install

```bash
git clone <your-fork> && cd macsec-agents
pip install -e .
# optional: NVD API key avoids heavy throttling (free at https://nvd.nist.gov/developers/request-an-api-key)
export NVD_API_KEY=...
# optional: local open-source LLM analysis
brew install ollama && ollama serve &  ollama pull llama3.1:8b
```

## Use

On your Mac mini M2:

```bash
macsec scan                 # full pipeline: inventory -> feeds -> match -> analyze -> harden -> report
macsec inventory --export inv.json   # collect inventory only
macsec audit                # hardening controls only
macsec audit --write-fix-script fix.sh   # reviewable remediation script
macsec agents               # show the team roster
macsec history              # scan history with MacSec Score trend
macsec diff                 # diff last two scans: new / resolved / newly-exploited findings
```

### Continuous monitoring in CI

Reports include a `SARIF` file — upload it to GitHub Code Scanning to turn Mac
vulnerability management into a CI gate:

```yaml
- run: macsec scan --inventory-file inv.json --no-nvd --no-llm
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: macsec-reports/  # picks up macsec-report-*.sarif
```

Analyze a Mac's inventory from anywhere (CI, another machine):

```bash
macsec scan --inventory-file inv.json --no-nvd
```

Other flags: `--offline` (cached feeds only), `--no-llm`, `--no-nvd`,
`--config config.yaml` (see `config.example.yaml`), `--output DIR`.

## How matching works

- **macOS CVEs**: a CVE from the Apple DB applies when your macOS version is older than
  the fixed version listed in its advisory (high confidence), or when the advisory covers
  your macOS major with no version data (low confidence).
- **Exploitation**: Apple's "may have been exploited" flag OR presence in CISA KEV
  promotes a finding to P1-CRITICAL and adds +2.0 to its composite score.
- **Third-party software**: NVD keyword lookups against your brew/cask/app inventory.

## Privacy & safety

- Collection commands are **read-only** (`sw_vers`, `system_profiler`, `brew list`,
  `csrutil status`, …). Nothing is changed on your Mac.
- The only network calls are to the public feeds listed above; no host data leaves the machine.
- The remediation script is generated for review — it prints guidance instead of
  auto-applying changes.

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests/     # end-to-end pipeline tests against recorded real feed fixtures
```

## License

MIT (see LICENSE). Apple CVE dataset courtesy of
[theevilbit/apple-cve-website](https://github.com/theevilbit/apple-cve-website);
please report data issues upstream there.
