"""Explicit pipeline settings.

Everything that used to be a hard-coded module constant in ``model_training.py`` lives
here so that it can be overridden per run (CLI, tests, notebooks) without editing code.
The BenchmarkJava source tree stays the default scan target.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Optional

from .triage import TriageSettings


# Repo root, so default paths work regardless of the working directory.
REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
RESULTS_DIR = REPO_ROOT / "results"
PROGRESS_DIR = REPO_ROOT / "progress"

DEFAULT_SOURCE_ROOT = Path("/home/Deus/Projects/BenchmarkJava/src/main/java")
DEFAULT_SEMGREP_INPUT = DATA_DIR / "semgrep" / "Semgrep-v1.0-results.json"
DEFAULT_OUTPUT_FILE = RESULTS_DIR / "llm_enhanced_sast.json"
DEFAULT_PROGRESS_FILE = PROGRESS_DIR / "llm_enhanced_progress.json"
DEFAULT_TRIAGE_REPORT_FILE = RESULTS_DIR / "triage_report.json"
DEFAULT_HIGHEST_CONFIDENCE_FILE = RESULTS_DIR / "llm_enhanced_sast_highest_confidence.json"
DEFAULT_LABELS_FILE = DATA_DIR / "labels" / "triage_labels.jsonl"

DEFAULT_ROBUST_MODEL = "qwen3.5:9b"
DEFAULT_SMALL_MODEL = "qwen3:4b"
DEFAULT_ANTHROPIC_MODEL = "claude-haiku-4-5"

BACKEND_OLLAMA = "ollama"
BACKEND_ANTHROPIC = "anthropic"
BACKEND_MUSE_SPARK = "muse-spark"
BACKEND_DEEPSEEK = "deepseek"

DEFAULT_MUSE_SPARK_MODEL = "muse-spark-1.3"
DEFAULT_DEEPSEEK_MODEL = "deepseek-flash"


@dataclass
class PipelineConfig:
    # Inputs / outputs
    source_root: Path = DEFAULT_SOURCE_ROOT
    semgrep_input: Path = DEFAULT_SEMGREP_INPUT
    output_file: Path = DEFAULT_OUTPUT_FILE
    progress_file: Path = DEFAULT_PROGRESS_FILE
    triage_report_file: Path = DEFAULT_TRIAGE_REPORT_FILE
    labels_file: Path = DEFAULT_LABELS_FILE

    # Robust (deep) model
    backend: str = BACKEND_OLLAMA          # "ollama" | "anthropic" | "muse-spark" | "deepseek"
    robust_model: str = DEFAULT_ROBUST_MODEL     # Ollama model tag
    muse_spark_api_key: Optional[str] = None
    muse_spark_model: str = DEFAULT_MUSE_SPARK_MODEL
    muse_spark_max_tokens: int = 8192      # reasoning tokens share this budget - keep generous
    muse_spark_reasoning_effort: Optional[str] = None  # unconfirmed param name; pass-through only
    deepseek_api_key: Optional[str] = None
    deepseek_model: str = DEFAULT_DEEPSEEK_MODEL
    deepseek_max_tokens: int = 8192
    anthropic_model: str = DEFAULT_ANTHROPIC_MODEL
    anthropic_max_tokens: int = 16000     # room for thinking tokens + the batch's analyses
    anthropic_workspace_id: Optional[str] = None   # for keys not scoped to a workspace
    anthropic_thinking: bool = False               # adaptive thinking (Sonnet/Opus)
    anthropic_effort: Optional[str] = None          # low | medium | high | xhigh | max
    anthropic_structured: bool = False             # constrain output via output_config.format
    # Append bodies of called project methods to the robust prompt (helper-class context).
    cross_file_context: bool = False
    # Vulnerability-class substrings whose findings skip the robust model and are recorded
    # as confirmed true positives (scanner precision already at ceiling on these).
    auto_confirm_classes: tuple = ()
    api_concurrency: int = 8              # thread-pool size for the anthropic sync path
    use_batch_api: bool = False           # anthropic backend: use the Message Batches API
    # Findings per model call. Small for the API backend: method-context prompts are
    # large and models silently drop findings from big batches.
    batch_size: int = 20
    num_ctx: int = 32768
    ollama_think: bool = False   # enable reasoning/thinking mode for local models (slower)
    ollama_num_predict: Optional[int] = None  # cap on local-model output tokens; None -> auto from batch_size
    timeout: int = 600           # seconds per deep-model call
    max_retries: int = 2         # retry timed-out / empty batches

    # Small (borderline) model. Off by default; fail-closed when on.
    enable_small_model: bool = False
    small_backend: str = BACKEND_OLLAMA        # "ollama" | "anthropic"
    small_model: str = DEFAULT_SMALL_MODEL     # Ollama model tag
    small_anthropic_model: str = DEFAULT_ANTHROPIC_MODEL
    small_model_timeout: int = 120
    small_model_num_ctx: int = 8192
    small_model_max_tokens: int = 400         # screener replies are one short JSON object

    # Deferral is a policy switch on top of triage: when False, findings the static
    # layer would defer are escalated instead (report still records "would defer").
    enable_deferral: bool = False

    # Bounded runs: analyze at most this many escalated findings (None = all).
    max_findings: Optional[int] = None

    triage: TriageSettings = field(default_factory=TriageSettings)

    def __post_init__(self):
        for name in ("source_root", "semgrep_input", "output_file", "progress_file",
                     "triage_report_file", "labels_file"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, Path):
                setattr(self, name, Path(value))

    def with_overrides(self, **changes) -> "PipelineConfig":
        return replace(self, **changes)

    def effective_robust_model(self) -> str:
        if self.backend == BACKEND_ANTHROPIC:
            return self.anthropic_model
        if self.backend == BACKEND_MUSE_SPARK:
            return self.muse_spark_model
        if self.backend == BACKEND_DEEPSEEK:
            return self.deepseek_model
        return self.robust_model

    def effective_small_model(self) -> str:
        return (self.small_anthropic_model if self.small_backend == BACKEND_ANTHROPIC
                else self.small_model)

    def concurrency(self) -> int:
        return (self.api_concurrency
                if self.backend in (BACKEND_ANTHROPIC, BACKEND_MUSE_SPARK, BACKEND_DEEPSEEK)
                else 1)

    def small_concurrency(self) -> int:
        return self.api_concurrency if self.small_backend == BACKEND_ANTHROPIC else 1

    def routing_fields(self) -> dict:
        """Settings that change which findings get analysed or how they are prompted.

        Any change here invalidates stored progress; cosmetic settings (paths, timeouts,
        retries) deliberately do not.
        """
        # Only what changes *which* findings get screened/analysed or *what model*
        # produces the analysis. Batch size, context window, concurrency and timeouts
        # are execution details and deliberately do not invalidate cached progress.
        return {
            "schema": 2,
            "semgrep_input": str(self.semgrep_input),
            "source_root": str(self.source_root),
            "backend": self.backend,
            "robust_model": self.effective_robust_model(),
            "anthropic_thinking": self.anthropic_thinking if self.backend == BACKEND_ANTHROPIC else None,
            "anthropic_effort": self.anthropic_effort if self.backend == BACKEND_ANTHROPIC else None,
            "anthropic_structured": self.anthropic_structured if self.backend == BACKEND_ANTHROPIC else None,
            "muse_spark_reasoning_effort": (self.muse_spark_reasoning_effort
                                            if self.backend == BACKEND_MUSE_SPARK else None),
            "cross_file_context": self.cross_file_context,
            "auto_confirm_classes": sorted(self.auto_confirm_classes or ()),
            "enable_small_model": self.enable_small_model,
            "small_model": self.effective_small_model() if self.enable_small_model else None,
            "small_backend": self.small_backend if self.enable_small_model else None,
            "enable_deferral": self.enable_deferral,
            "triage": self.triage.to_dict(),
        }

    def fingerprint(self) -> str:
        payload = json.dumps(self.routing_fields(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        data = {
            "source_root": str(self.source_root),
            "semgrep_input": str(self.semgrep_input),
            "output_file": str(self.output_file),
            "progress_file": str(self.progress_file),
            "triage_report_file": str(self.triage_report_file),
            "labels_file": str(self.labels_file),
            "backend": self.backend,
            "robust_model": self.robust_model,
            "anthropic_model": self.anthropic_model,
            "anthropic_max_tokens": self.anthropic_max_tokens,
            "anthropic_thinking": self.anthropic_thinking,
            "anthropic_effort": self.anthropic_effort,
            "anthropic_structured": self.anthropic_structured,
            "muse_spark_model": self.muse_spark_model,
            "muse_spark_max_tokens": self.muse_spark_max_tokens,
            "muse_spark_reasoning_effort": self.muse_spark_reasoning_effort,
            "muse_spark_api_key_set": bool(self.muse_spark_api_key),
            "deepseek_model": self.deepseek_model,
            "deepseek_max_tokens": self.deepseek_max_tokens,
            "deepseek_api_key_set": bool(self.deepseek_api_key),
            "cross_file_context": self.cross_file_context,
            "auto_confirm_classes": list(self.auto_confirm_classes or ()),
            "anthropic_workspace_id_set": bool(self.anthropic_workspace_id),
            "api_concurrency": self.api_concurrency,
            "use_batch_api": self.use_batch_api,
            "effective_robust_model": self.effective_robust_model(),
            "batch_size": self.batch_size,
            "num_ctx": self.num_ctx,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "enable_small_model": self.enable_small_model,
            "small_backend": self.small_backend,
            "small_model": self.small_model,
            "small_anthropic_model": self.small_anthropic_model,
            "effective_small_model": self.effective_small_model(),
            "small_model_timeout": self.small_model_timeout,
            "small_model_num_ctx": self.small_model_num_ctx,
            "enable_deferral": self.enable_deferral,
            "max_findings": self.max_findings,
            "triage": self.triage.to_dict(),
        }
        data["fingerprint"] = self.fingerprint()
        return data
