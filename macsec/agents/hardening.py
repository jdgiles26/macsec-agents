"""HardeningAgent: CIS-style macOS audit checks with remediation guidance.

Each check declares an audit command (read-only) and an evaluator. On
non-macOS hosts checks against a loaded inventory's posture snapshot; live
command execution only happens on macOS.
"""

from __future__ import annotations

from macsec.agents.base import Agent
from macsec.models import HardeningCheck


# (id, title, category, severity, posture-field, expected, remediation)
POSTURE_CHECKS = [
    ("MACSEC-SIP-001", "System Integrity Protection enabled", "system", "high",
     "sip_enabled", True,
     "Boot into Recovery OS and run `csrutil enable`. Never ship a Mac with SIP off."),
    ("MACSEC-FV-001", "FileVault full-disk encryption on", "encryption", "high",
     "filevault_enabled", True,
     "System Settings -> Privacy & Security -> FileVault -> Turn On, or `sudo fdesetup enable`."),
    ("MACSEC-FW-001", "Application firewall enabled", "network", "medium",
     "firewall_enabled", True,
     "`sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on`."),
    ("MACSEC-FW-002", "Firewall stealth mode enabled", "network", "low",
     "firewall_stealth", True,
     "`sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on`."),
    ("MACSEC-GK-001", "Gatekeeper enabled", "system", "high",
     "gatekeeper_enabled", True,
     "`sudo spctl --master-enable`. Blocks unsigned/unnotarized apps."),
    ("MACSEC-UPD-001", "Automatic update checks enabled", "updates", "high",
     "automatic_updates", True,
     "System Settings -> General -> Software Update -> Automatic Updates: enable all."),
    ("MACSEC-SSH-001", "Remote Login (SSH) disabled unless needed", "services", "medium",
     "remote_login_ssh", False,
     "`sudo systemsetup -setremotelogin off` when remote access is not required."),
]


class HardeningAgent(Agent):
    name = "hardening-auditor"
    role = "hardening"
    description = "Audits macOS security controls (SIP, FileVault, firewall, Gatekeeper, updates)"

    def run(self) -> list[HardeningCheck]:
        inv = self.ctx.inventory
        checks: list[HardeningCheck] = []
        for cid, title, cat, sev, field_name, expected, fix in POSTURE_CHECKS:
            chk = HardeningCheck(check_id=cid, title=title, category=cat,
                                 severity=sev, remediation=fix, expected=str(expected))
            observed = getattr(inv.posture, field_name, None) if inv else None
            if observed is None:
                chk.status = "unknown" if (inv and inv.is_macos) else "skipped"
                chk.observed = "not collected"
            else:
                chk.observed = str(observed)
                chk.status = "pass" if observed == expected else "fail"
            checks.append(chk)

        checks.append(self._check_os_currency(inv))
        checks.append(self._check_unsigned_apps(inv))

        self.ctx.analysis.hardening = checks
        fails = sum(1 for c in checks if c.status == "fail")
        self.ctx.analysis.stats["hardening_fail"] = fails
        self.log(f"{len(checks)} controls audited, {fails} failing"
                 + (" - hardening required" if fails else ""))
        return checks

    def _check_os_currency(self, inv) -> HardeningCheck:
        chk = HardeningCheck(
            check_id="MACSEC-UPD-002", title="macOS on latest security release",
            category="updates", severity="high",
            audit_command="sw_vers vs support.apple.com/en-us/100100",
            remediation="Install the latest macOS security update immediately.",
            references=["https://support.apple.com/en-us/100100"],
        )
        latest = ""
        for feed in self.ctx.feeds:
            if feed.source == "apple-releases":
                releases = feed.meta.get("macos_releases", [])
                versions = [r["version"] for r in releases]
                if versions and inv:
                    same_major = [v for v in versions
                                  if v.split(".")[0] == str(inv.macos_major)]
                    pool = same_major or versions
                    from macsec.utils import parse_version
                    latest = max(pool, key=lambda v: parse_version(v) or parse_version("0"))
        if not inv or not inv.is_macos:
            chk.status, chk.observed = "skipped", "not macOS"
        elif not latest:
            chk.status, chk.observed = "unknown", inv.macos_product_version
            chk.expected = "latest release unknown (feed unavailable)"
        else:
            from macsec.utils import version_lt
            chk.observed = inv.macos_product_version
            chk.expected = f">= {latest}"
            chk.status = "fail" if version_lt(inv.macos_product_version, latest) else "pass"
        return chk

    MAX_APPS_AUDITED = 60

    def _check_unsigned_apps(self, inv) -> HardeningCheck:
        """Audit /Applications for unsigned or unnotarized apps via spctl/codesign."""
        chk = HardeningCheck(
            check_id="MACSEC-APP-001",
            title="Installed apps are signed and notarized",
            category="system", severity="high",
            audit_command="spctl -a -t exec -vv /Applications/*.app",
            remediation="Remove or replace unsigned/unnotarized apps; they bypass "
                        "Gatekeeper protections and are a common malware vector.",
            references=["https://support.apple.com/guide/security/gatekeeper-sec5599b66df/web"],
        )
        if not inv or not inv.is_macos:
            chk.status, chk.observed = "skipped", "not macOS"
            return chk

        from pathlib import Path
        from macsec.utils import run_command
        apps = sorted(Path("/Applications").glob("*.app"))[: self.MAX_APPS_AUDITED]
        if not apps:
            chk.status, chk.observed = "unknown", "no apps found in /Applications"
            return chk
        rejected: list[str] = []
        for app in apps:
            rc, out, err = run_command(["spctl", "-a", "-t", "exec", "-vv", str(app)],
                                       timeout=10)
            verdict = (out + " " + err).lower()
            if rc != 0 or "rejected" in verdict:
                rejected.append(app.name)
        if rejected:
            chk.status = "fail"
            chk.observed = f"{len(rejected)} unsigned/unnotarized: {', '.join(rejected[:5])}"
        else:
            chk.status = "pass"
            chk.observed = f"{len(apps)} apps assessed, all accepted"
        return chk

    # ------------------------------------------------- remediation script

    @staticmethod
    def remediation_script(checks: list[HardeningCheck]) -> str:
        """Generate a reviewable shell script of manual remediation steps."""
        lines = ["#!/bin/zsh", "# macsec-agents remediation guide - REVIEW BEFORE RUNNING",
                 "# Generated for failing hardening controls.", "set -e", ""]
        for c in checks:
            if c.status != "fail":
                continue
            lines += [f"echo '--- [{c.check_id}] {c.title}'",
                      f"echo 'Observed: {c.observed} | Expected: {c.expected}'",
                      f"echo 'Action:  {c.remediation}'", "echo ''"]
        if len(lines) == 5:
            lines.append("echo 'No failing controls - nothing to do.'")
        return "\n".join(lines) + "\n"
