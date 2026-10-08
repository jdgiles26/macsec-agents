"""Configuration loading for macsec-agents."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class Config:
    # feeds
    apple_cve_index_url: str = (
        "https://raw.githubusercontent.com/theevilbit/apple-cve-website/main/api/index.json"
    )
    apple_cve_db_url: str = (  # legacy monolithic db (fallback if the API index is gone)
        "https://raw.githubusercontent.com/theevilbit/apple-cve-website/main/data/db.json"
    )
    apple_cve_years: int = 0          # 0 = all years; N = only the last N years
    cisa_kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    apple_releases_url: str = "https://support.apple.com/en-us/100100"
    epss_url: str = "https://api.first.org/data/v1/epss"
    epss_batch: int = 50
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str = ""               # or env NVD_API_KEY
    nvd_max_products: int = 40          # cap third-party keyword lookups
    feed_ttl: int = 3600                # seconds; feed cache lifetime

    # pipeline switches
    offline: bool = False
    enable_nvd: bool = True
    enable_kev: bool = True
    enable_apple_releases: bool = True
    enable_epss: bool = True
    enable_llm: bool = True
    enable_history: bool = True

    # llm (local open-source model via Ollama)
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.1:8b"
    llm_timeout: int = 120
    llm_max_findings: int = 15

    # output
    output_dir: str = "./macsec-reports"
    report_formats: list[str] = field(default_factory=lambda: ["json", "md", "html", "sarif"])

    @staticmethod
    def load(path: Optional[str]) -> "Config":
        cfg = Config()
        if path:
            p = Path(path).expanduser()
            if not p.exists():
                raise FileNotFoundError(f"config not found: {p}")
            data = yaml.safe_load(p.read_text()) or {}
            for k, v in data.items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)
        if not cfg.nvd_api_key:
            cfg.nvd_api_key = os.environ.get("NVD_API_KEY", "")
        return cfg
