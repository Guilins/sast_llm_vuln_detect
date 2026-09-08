"""Per-finding resumable progress, keyed by stable finding identity and guarded by
the configuration fingerprint."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


PROGRESS_SCHEMA = 2


@dataclass
class ProgressState:
    """Per-finding progress keyed by stable finding identity.

    A stored state is only reused when its ``fingerprint`` matches the current
    configuration; otherwise it is discarded so that results produced under a different
    routing/prompt configuration are never spliced into a new run.
    """

    fingerprint: str
    completed: dict = field(default_factory=dict)      # key -> analysis dict
    failed_keys: list = field(default_factory=list)
    small_model: dict = field(default_factory=dict)    # key -> verdict dict

    def to_dict(self) -> dict:
        return {
            "schema": PROGRESS_SCHEMA,
            "fingerprint": self.fingerprint,
            "completed_analyses": self.completed,
            "failed_keys": self.failed_keys,
            "small_model_verdicts": self.small_model,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ProgressState":
        return cls(
            fingerprint=data.get("fingerprint", ""),
            completed=dict(data.get("completed_analyses") or {}),
            failed_keys=list(data.get("failed_keys") or []),
            small_model=dict(data.get("small_model_verdicts") or {}),
        )


def load_progress(progress_file, fingerprint, log=print) -> ProgressState:
    """Load progress if (and only if) it was produced by the same configuration."""
    progress_file = Path(progress_file)
    if not progress_file.exists():
        return ProgressState(fingerprint)
    try:
        with open(progress_file, "r") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        log(f"  ⚠ progress file unreadable ({exc}); starting fresh")
        return ProgressState(fingerprint)

    if not isinstance(data, dict) or data.get("schema") != PROGRESS_SCHEMA:
        log("  ⚠ progress file uses an older schema (batch-keyed); starting fresh")
        return ProgressState(fingerprint)
    if data.get("fingerprint") != fingerprint:
        log(f"  ⚠ progress fingerprint {data.get('fingerprint')} != current {fingerprint}; starting fresh")
        return ProgressState(fingerprint)
    return ProgressState.from_dict(data)


def save_progress(progress_file, state: ProgressState):
    """Persist progress atomically so an interrupted write never corrupts the file."""
    progress_file = Path(progress_file)
    tmp = progress_file.with_suffix(progress_file.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(state.to_dict(), f)
    os.replace(tmp, progress_file)
