"""Utilities: HTTP with disk cache, subprocess wrappers, version compare."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import time
from pathlib import Path
from typing import Optional

import requests
from packaging.version import Version, InvalidVersion

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "macsec-agents"
USER_AGENT = "macsec-agents/1.0 (+https://github.com/theevilbit/apple-cve-website consumer)"


def cache_dir() -> Path:
    d = Path(os.environ.get("MACSEC_CACHE_DIR", DEFAULT_CACHE_DIR))
    d.mkdir(parents=True, exist_ok=True)
    return d


def http_get(url: str, *, ttl: int = 3600, offline: bool = False,
             timeout: int = 60, headers: Optional[dict] = None) -> bytes:
    """GET a URL with an on-disk cache. In offline mode only the cache is used."""
    key = hashlib.sha256(url.encode()).hexdigest()[:32]
    blob = cache_dir() / f"{key}.bin"
    meta = cache_dir() / f"{key}.meta.json"

    if meta.exists() and blob.exists():
        age = time.time() - json.loads(meta.read_text()).get("ts", 0)
        if offline or age < ttl:
            return blob.read_bytes()

    if offline:
        raise RuntimeError(f"offline mode: no cached copy of {url}")

    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            resp = requests.get(url, headers=hdrs, timeout=timeout)
            resp.raise_for_status()
            blob.write_bytes(resp.content)
            meta.write_text(json.dumps({"ts": time.time(), "url": url}))
            return resp.content
        except requests.RequestException as exc:  # noqa: PERF203
            last_err = exc
            time.sleep(1.5 * (attempt + 1))
    if blob.exists():  # stale cache beats no data
        return blob.read_bytes()
    raise RuntimeError(f"failed to fetch {url}: {last_err}")


def run_command(cmd: list[str], *, timeout: int = 30) -> tuple[int, str, str]:
    """Run a local command safely (no shell). Returns (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {' '.join(cmd)}"


def is_macos() -> bool:
    return platform.system() == "Darwin"


def is_apple_silicon() -> bool:
    return is_macos() and platform.machine() == "arm64"


def parse_version(text: str) -> Optional[Version]:
    """Best-effort version parse; None when unparseable."""
    text = (text or "").strip()
    if not text:
        return None
    m = re.search(r"\d+(?:\.\d+){0,3}(?:[a-zA-Z0-9.+-]*)?", text)
    if not m:
        return None
    try:
        return Version(m.group(0))
    except InvalidVersion:
        cleaned = re.sub(r"[^0-9.]", "", m.group(0)).strip(".")
        try:
            return Version(cleaned) if cleaned else None
        except InvalidVersion:
            return None


def version_lt(a: str, b: str) -> bool:
    va, vb = parse_version(a), parse_version(b)
    if va is None or vb is None:
        return False
    return va < vb


def severity_of(score: Optional[float]) -> str:
    if not score:
        return "UNSCORED"
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def mirror_urls(url: str) -> list[str]:
    """Alternative CDN URLs for a raw.githubusercontent.com URL (jsDelivr)."""
    m = re.match(r"https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)", url)
    if not m:
        return []
    owner, repo, branch, path = m.groups()
    return [f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}"]
