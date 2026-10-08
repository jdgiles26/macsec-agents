"""macsec CLI: command interface to the agent team."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from macsec.config import Config
from macsec.orchestrator import TEAM_ROSTER, Orchestrator

app = typer.Typer(
    name="macsec",
    help="Agentic security team for Apple silicon Macs: inventory, CVE intelligence, "
         "matching, risk analysis, hardening and reporting.",
    no_args_is_help=True,
)
console = Console()


def _cfg(config: Optional[str], offline: bool, no_nvd: bool, no_llm: bool,
         output: Optional[str]) -> Config:
    cfg = Config.load(config)
    if offline:
        cfg.offline = True
    if no_nvd:
        cfg.enable_nvd = False
    if no_llm:
        cfg.enable_llm = False
    if output:
        cfg.output_dir = output
    return cfg


@app.command()
def scan(
    config: Optional[str] = typer.Option(None, "--config", "-c", help="YAML config file"),
    inventory_file: Optional[str] = typer.Option(None, "--inventory-file", "-i",
        help="Analyse an exported inventory JSON instead of live collection"),
    offline: bool = typer.Option(False, "--offline", help="Use cached feeds only"),
    no_nvd: bool = typer.Option(False, "--no-nvd", help="Skip per-product NVD lookups"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip the Ollama LLM analyst"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Report directory"),
) -> None:
    """Full pipeline: inventory -> feeds -> match -> analyze -> harden -> report."""
    cfg = _cfg(config, offline, no_nvd, no_llm, output)
    orch = Orchestrator(cfg, inventory_file=inventory_file)
    artifacts = orch.run_full_pipeline()
    score = orch.ctx.analysis.stats.get("macsec_score")
    if score:
        console.print(f"\n[bold]MacSec Score: {score['score']}/100 "
                      f"(grade {score['grade']})[/]")
    console.print("\n[bold green]Scan complete.[/] Reports:")
    for fmt, path in artifacts.items():
        console.print(f"  {fmt:5} {path}")


@app.command()
def inventory(
    export: Optional[str] = typer.Option(None, "--export", "-e",
        help="Write collected inventory to a JSON file"),
) -> None:
    """Collect host inventory only (run on the target Mac)."""
    from macsec.agents.base import OrchestrationContext
    from macsec.agents.inventory import InventoryCollectorAgent

    cfg = Config.load(None)
    ctx = OrchestrationContext(config=cfg)
    inv = InventoryCollectorAgent(ctx).timed_run()

    table = Table(title="Host inventory")
    table.add_column("Field"); table.add_column("Value")
    for field in ("hostname", "model", "chip", "arch", "macos_product_version",
                  "macos_build", "kernel"):
        table.add_row(field, str(getattr(inv, field) or "-"))
    table.add_row("software items", str(len(inv.software)))
    console.print(table)

    if export:
        Path(export).write_text(json.dumps(inv.to_dict(), indent=2))
        console.print(f"[green]inventory exported to {export}[/]")


@app.command()
def audit(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    inventory_file: Optional[str] = typer.Option(None, "--inventory-file", "-i"),
    fix_script: Optional[str] = typer.Option(None, "--write-fix-script",
        help="Write a reviewable remediation script for failing controls"),
) -> None:
    """Hardening audit only: CIS-style control checks with remediation."""
    cfg = _cfg(config, offline=False, no_nvd=True, no_llm=True, output=None)
    checks = Orchestrator(cfg, inventory_file=inventory_file).run_audit_only()

    table = Table(title="Hardening audit")
    for col in ("ID", "Control", "Severity", "Status", "Observed", "Expected"):
        table.add_column(col)
    for c in checks:
        style = {"pass": "green", "fail": "red"}.get(c.status, "yellow")
        table.add_row(c.check_id, c.title, c.severity,
                      f"[{style}]{c.status.upper()}[/]", c.observed, c.expected)
    console.print(table)

    fails = [c for c in checks if c.status == "fail"]
    for c in fails:
        console.print(f"[red]{c.check_id}[/] {c.title}\n  -> {c.remediation}")

    if fix_script:
        from macsec.agents.hardening import HardeningAgent
        Path(fix_script).write_text(HardeningAgent.remediation_script(checks))
        console.print(f"[green]remediation script written to {fix_script} (review before running)[/]")


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n", help="How many past scans to show"),
) -> None:
    """Show recorded scan history (MacSec Score trend)."""
    from macsec.history import HistoryStore
    scans = HistoryStore().list_scans(limit)
    if not scans:
        console.print("[yellow]No scans recorded yet. Run `macsec scan` first.[/]")
        raise typer.Exit(0)
    table = Table(title="Scan history")
    for col in ("ID", "Timestamp", "Host", "macOS", "Score", "Grade", "Findings"):
        table.add_column(col)
    for s in scans:
        stats = json.loads(s.get("stats_json") or "{}")
        table.add_row(str(s["id"]), s["ts"], s.get("hostname") or "-",
                      s.get("macos") or "-", str(s.get("macsec_score") or "-"),
                      s.get("grade") or "-", str(stats.get("total_matches", "-")))
    console.print(table)


@app.command()
def diff(
    old: Optional[int] = typer.Argument(None, help="Older scan id (default: second-latest)"),
    new: Optional[int] = typer.Argument(None, help="Newer scan id (default: latest)"),
) -> None:
    """Diff two scans: new findings, resolved findings, score movement."""
    from macsec.history import HistoryStore
    store = HistoryStore()
    if old is None or new is None:
        scans = store.list_scans(2)
        if len(scans) < 2:
            console.print("[yellow]Need at least two recorded scans. "
                          "Run `macsec scan` again later.[/]")
            raise typer.Exit(0)
        new = new or scans[0]["id"]
        old = old or scans[1]["id"]
    d = store.diff(old, new)
    if d is None:
        console.print(f"[red]scan id not found (old={old}, new={new})[/]")
        raise typer.Exit(1)

    delta = d["score_delta"]
    console.print(f"\n[bold]Scan #{d['old_scan']['id']} -> #{d['new_scan']['id']}[/]  "
                  f"macOS {d['old_scan']['macos']} -> {d['new_scan']['macos']}  "
                  f"MacSec Score {d['grade_old']} -> {d['grade_new']} "
                  f"([{'green' if delta >= 0 else 'red'}]{delta:+.1f}[/])")

    def _table(title: str, rows: list[dict], style: str) -> None:
        if not rows:
            return
        t = Table(title=title)
        for col in ("CVE", "Target", "Tier", "Score", "Exploited"):
            t.add_column(col)
        for f in rows[:25]:
            t.add_row(f["cve_id"], f["target"], f["tier"] or "-",
                      str(f["score"] or "-"), "YES" if f["exploited"] else "")
        console.print(t)

    _table(f"New findings ({len(d['new_findings'])})", d["new_findings"], "red")
    _table(f"Resolved findings ({len(d['resolved_findings'])})", d["resolved_findings"], "green")
    _table(f"Newly exploited ({len(d['newly_exploited'])})", d["newly_exploited"], "red")
    if not (d["new_findings"] or d["resolved_findings"] or d["newly_exploited"]):
        console.print("[green]No change in findings between the two scans.[/]")


@app.command()
def agents() -> None:
    """List the agent team roster."""
    table = Table(title="macsec agent team")
    table.add_column("Agent"); table.add_column("Role"); table.add_column("Mission")
    for name, role, desc in TEAM_ROSTER:
        table.add_row(name, role, desc)
    console.print(table)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
