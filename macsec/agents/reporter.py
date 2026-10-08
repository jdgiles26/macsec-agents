"""ReporterAgent: renders the full analysis into JSON, Markdown and HTML."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from macsec.agents.base import Agent
from macsec.models import utcnow

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"


class ReporterAgent(Agent):
    name = "reporter"
    role = "documentation"
    description = "Produces JSON, Markdown and HTML security reports"

    def run(self) -> dict[str, str]:
        out_dir = Path(self.cfg.output_dir).expanduser().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = utcnow().replace(":", "").replace("-", "").replace("Z", "")

        payload = self._payload()
        written: dict[str, str] = {}

        if "json" in self.cfg.report_formats:
            p = out_dir / f"macsec-report-{stamp}.json"
            p.write_text(json.dumps(payload, indent=2))
            written["json"] = str(p)
        if "sarif" in self.cfg.report_formats:
            from macsec.sarif import build_sarif
            inv = self.ctx.inventory
            host = f"{inv.model} {inv.chip}".strip() if inv else ""
            p = out_dir / f"macsec-report-{stamp}.sarif"
            p.write_text(json.dumps(build_sarif(self.ctx.analysis, host), indent=2))
            written["sarif"] = str(p)

        env = Environment(loader=FileSystemLoader(str(TEMPLATES)),
                          autoescape=select_autoescape(["html"]),
                          trim_blocks=True, lstrip_blocks=True)
        if "md" in self.cfg.report_formats:
            p = out_dir / f"macsec-report-{stamp}.md"
            p.write_text(env.get_template("report.md.j2").render(**payload))
            written["md"] = str(p)
        if "html" in self.cfg.report_formats:
            p = out_dir / f"macsec-report-{stamp}.html"
            p.write_text(env.get_template("report.html.j2").render(**payload))
            written["html"] = str(p)

        self.ctx.artifacts.update(written)
        self.log("reports written: " + ", ".join(written.values()))
        return written

    def _payload(self) -> dict:
        inv = self.ctx.inventory
        a = self.ctx.analysis
        return {
            "generated_at": utcnow(),
            "inventory": inv.to_dict() if inv else None,
            "feeds": [{"source": f.source, "fetched_at": f.fetched_at,
                       "records": len(f.records), "meta": f.meta,
                       "errors": f.errors} for f in self.ctx.feeds],
            "matches": [asdict(m) for m in a.matches],
            "risks": [{**asdict(r), "match": asdict(r.match)} for r in a.risks],
            "hardening": [asdict(c) for c in a.hardening],
            "llm_summary": a.llm_summary,
            "llm_model": a.llm_model,
            "stats": a.stats,
            "events": [asdict(e) for e in self.ctx.events],
        }
