"""Agent framework: base class, shared context, event log."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from rich.console import Console

from macsec.config import Config
from macsec.models import AnalysisResult, FeedResult, Inventory

console = Console(stderr=True)


@dataclass
class Event:
    ts: str
    agent: str
    message: str
    level: str = "info"


@dataclass
class OrchestrationContext:
    """Shared blackboard every agent reads from and writes to."""

    config: Config
    inventory: Optional[Inventory] = None
    feeds: list[FeedResult] = field(default_factory=list)
    analysis: AnalysisResult = field(default_factory=AnalysisResult)
    events: list[Event] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)   # name -> file path

    def log(self, agent: str, message: str, level: str = "info") -> None:
        from macsec.models import utcnow
        self.events.append(Event(utcnow(), agent, message, level))
        style = {"info": "cyan", "warn": "yellow", "error": "red", "ok": "green"}.get(level, "white")
        console.print(f"[{style}][{agent}][/{style}] {message}")


class Agent:
    """Base class for every agent in the team."""

    name: str = "agent"
    role: str = "generic"
    description: str = ""

    def __init__(self, ctx: OrchestrationContext):
        self.ctx = ctx

    @property
    def cfg(self) -> Config:
        return self.ctx.config

    def log(self, message: str, level: str = "info") -> None:
        self.ctx.log(self.name, message, level)

    def run(self) -> Any:  # pragma: no cover - overridden
        raise NotImplementedError

    def timed_run(self) -> Any:
        start = time.time()
        self.log(f"starting ({self.role})")
        try:
            result = self.run()
        except Exception as exc:
            self.log(f"failed: {exc}", "error")
            raise
        self.log(f"done in {time.time() - start:.1f}s", "ok")
        return result


TEAM: list[dict] = []  # populated by orchestrator for `macsec agents`
