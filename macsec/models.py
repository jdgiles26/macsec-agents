"""Shared data models for the macsec agent pipeline.

All agents communicate through these dataclasses attached to the
OrchestrationContext, so every stage is independently testable and the
pipeline stays strongly typed end to end.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Optional


# ---------------------------------------------------------------- inventory

@dataclass
class SoftwareItem:
    """One installed piece of software discovered on the machine."""

    name: str
    version: str = ""
    source: str = ""          # brew | brew-cask | pip | system_profiler | apple
    vendor: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class SecurityPosture:
    """Point-in-time snapshot of macOS security-relevant settings."""

    sip_enabled: Optional[bool] = None
    filevault_enabled: Optional[bool] = None
    firewall_enabled: Optional[bool] = None
    firewall_stealth: Optional[bool] = None
    gatekeeper_enabled: Optional[bool] = None
    automatic_updates: Optional[bool] = None
    xprotect_version: str = ""
    remote_login_ssh: Optional[bool] = None
    details: dict = field(default_factory=dict)


@dataclass
class Inventory:
    """Everything the collector agents learned about the host."""

    hostname: str = ""
    collected_at: str = ""
    platform: str = ""            # e.g. "Darwin"
    is_macos: bool = False
    model: str = ""               # e.g. "Mac mini"
    chip: str = ""                # e.g. "Apple M2"
    arch: str = ""                # e.g. "arm64"
    macos_product_version: str = ""   # e.g. "14.6.1"
    macos_build: str = ""
    macos_major: int = 0
    kernel: str = ""
    software: list[SoftwareItem] = field(default_factory=list)
    posture: SecurityPosture = field(default_factory=SecurityPosture)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict) -> "Inventory":
        inv = Inventory()
        for k, v in data.items():
            if k == "software":
                inv.software = [SoftwareItem(**s) for s in v]
            elif k == "posture":
                inv.posture = SecurityPosture(**v)
            elif hasattr(inv, k):
                setattr(inv, k, v)
        return inv


# ---------------------------------------------------------------- CVE feeds

@dataclass
class CVERecord:
    """A normalized CVE observation from any feed."""

    cve_id: str
    source: str                     # apple-cve-website | nvd | cisa-kev | apple-releases
    description: str = ""
    component: str = ""
    impact: str = ""
    impact_class: str = ""
    cvss: Optional[float] = None
    severity: str = ""              # CRITICAL/HIGH/MEDIUM/LOW/UNSCORED
    exploited: bool = False         # actively exploited (Apple wording or CISA KEV)
    date_published: str = ""
    advisory_title: str = ""
    advisory_url: str = ""
    platforms: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    affected_product: str = ""
    references: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)


@dataclass
class FeedResult:
    """Output of one feed agent."""

    source: str
    fetched_at: str = ""
    records: list[CVERecord] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- analysis

@dataclass
class Match:
    """A CVE linked to something on this machine (OS or installed software)."""

    cve: CVERecord
    target: str                     # "macOS" or software name
    target_version: str
    match_kind: str                 # os-version | fixed-version | keyword | kev-flag
    confidence: str = "medium"      # high | medium | low
    rationale: str = ""


@dataclass
class RiskAssessment:
    """Risk scoring for one matched CVE."""

    match: Match
    score: float = 0.0              # 0-10 composite
    tier: str = "LOW"               # P1-CRITICAL | P2-HIGH | P3-MEDIUM | P4-LOW
    factors: list[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class HardeningCheck:
    """One CIS-style hardening control and its audit result."""

    check_id: str
    title: str
    category: str                   # system | network | updates | encryption | services
    severity: str                   # high | medium | low
    status: str = "unknown"         # pass | fail | unknown | skipped
    observed: str = ""
    expected: str = ""
    audit_command: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    matches: list[Match] = field(default_factory=list)
    risks: list[RiskAssessment] = field(default_factory=list)
    hardening: list[HardeningCheck] = field(default_factory=list)
    llm_summary: str = ""
    llm_model: str = ""
    stats: dict = field(default_factory=dict)


def utcnow() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
