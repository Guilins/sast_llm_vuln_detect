"""Layer-1 static triage for Semgrep findings.

This module is intentionally dependency-free (standard library only). It turns a raw
Semgrep result into a deterministic, transparent ``TriageDecision`` that says whether the
finding must go to the robust LLM (``escalate``), may first be screened by a cheap small
model (``borderline``), or can be skipped (``defer``).

The policy favours recall: hard guards always escalate ``ERROR``/``WARNING`` severities,
findings with missing metadata or unreadable code context, and findings that carry a
high-risk static signal. Deferral only happens when no guard fires and the transparent
risk score falls below the configured borderline threshold.
"""

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

ACTION_ESCALATE = "escalate"
ACTION_BORDERLINE = "borderline"
ACTION_DEFER = "defer"
ACTIONS = (ACTION_ESCALATE, ACTION_BORDERLINE, ACTION_DEFER)

BAND_HIGH = "high"
BAND_MEDIUM = "medium"
BAND_LOW = "low"

GUARD_SEVERITY_ERROR = "severity_error"
GUARD_SEVERITY_WARNING = "severity_warning"
GUARD_MISSING_METADATA = "missing_metadata"
GUARD_MISSING_CONTEXT = "missing_context"
GUARD_HIGH_RISK_SIGNAL = "high_risk_signal"

SNIPPET_OK = "ok"
SNIPPET_NO_SOURCE_ROOT = "no_source_root"
SNIPPET_NO_PATH = "no_path"
SNIPPET_OUTSIDE_ROOT = "outside_root"
SNIPPET_FILE_NOT_FOUND = "file_not_found"
SNIPPET_UNREADABLE = "unreadable"
SNIPPET_TOO_LARGE = "too_large"
SNIPPET_LINE_OUT_OF_RANGE = "line_out_of_range"

CONTROL_KEYWORDS = ("if", "for", "while", "switch", "catch", "synchronized", "try", "else", "do")

KNOWN_SEVERITIES = ("ERROR", "WARNING", "INFO")
KNOWN_CONFIDENCES = ("HIGH", "MEDIUM", "LOW")

MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024


# ---------------------------------------------------------------------------
# Settings (thresholds, guards, weights)
# ---------------------------------------------------------------------------

DEFAULT_THRESHOLDS = {
    # score >= escalate_at  -> escalate even without a hard guard
    "escalate_at": 0.60,
    # borderline_at <= score < escalate_at -> borderline (small model, if enabled)
    "borderline_at": 0.30,
}

# Vulnerability classes where a Benchmark-style false positive is plausible: the finding
# hinges on whether a sanitizer/validator is applied or a branch is reachable, which a
# small model can often resolve by reading the enclosing method. Substring match against
# the lower-cased vulnerability_class. Crypto/hash/weak-random/cookie findings are left
# out on purpose — they are almost always real and cheap for the robust model to confirm.
DEFAULT_BORDERLINE_CLASSES = (
    "sql injection",
    "cross-site-scripting",
    "xss",
    "path traversal",
    "command injection",
    "ldap injection",
    "xpath injection",
)

SEVERITY_RANK = {"ERROR": 3, "WARNING": 2, "INFO": 1}

DEFAULT_GUARDS = {
    GUARD_SEVERITY_ERROR: True,
    GUARD_SEVERITY_WARNING: True,
    GUARD_MISSING_METADATA: True,
    GUARD_MISSING_CONTEXT: True,
    GUARD_HIGH_RISK_SIGNAL: True,
}

DEFAULT_WEIGHTS = {
    "severity:ERROR": 0.35,
    "severity:WARNING": 0.20,
    "severity:INFO": 0.05,
    "confidence:HIGH": 0.20,
    "confidence:MEDIUM": 0.10,
    "confidence:LOW": 0.0,
    "impact:HIGH": 0.10,
    "impact:MEDIUM": 0.05,
    "likelihood:HIGH": 0.10,
    "likelihood:MEDIUM": 0.05,
    "cwe_top25": 0.10,
    "subcategory:vuln": 0.10,
    "subcategory:audit": 0.0,
    "taint_source": 0.10,
    "source_sink_combo": 0.20,
    "sanitizer_hint": -0.10,
    "missing_metadata": 0.30,
    "missing_context": 0.30,
}


@dataclass
class TriageSettings:
    """Tunable knobs for static triage. ``weights`` overrides individual defaults."""

    thresholds: dict = field(default_factory=lambda: dict(DEFAULT_THRESHOLDS))
    guards: dict = field(default_factory=lambda: dict(DEFAULT_GUARDS))
    weights: dict = field(default_factory=dict)
    context_lines: int = 6
    # Focal code for scoring/screening: the enclosing method (brace-matched), falling
    # back to +-this many lines when the method cannot be bounded or is too big.
    method_context_fallback_lines: int = 40
    max_method_lines: int = 400
    # Vulnerability classes eligible for small-model screening instead of direct escalation.
    borderline_classes: tuple = DEFAULT_BORDERLINE_CLASSES
    # Only findings at or below this severity may be routed borderline; higher severities
    # always escalate. Default "WARNING" keeps the plan's "always escalate ERROR" guard.
    borderline_max_severity: str = "WARNING"
    # Rough cost of one finding inside a deep-model batch (prompt + completion).
    est_tokens_per_finding: int = 700

    def effective_weights(self) -> dict:
        merged = dict(DEFAULT_WEIGHTS)
        merged.update({spec.weight_key: spec.weight for spec in SIGNAL_SPECS})
        merged.update(self.weights)
        return merged

    def to_dict(self) -> dict:
        return {
            "thresholds": dict(self.thresholds),
            "guards": dict(self.guards),
            "weights": dict(self.weights),
            "context_lines": self.context_lines,
            "method_context_fallback_lines": self.method_context_fallback_lines,
            "max_method_lines": self.max_method_lines,
            "borderline_classes": list(self.borderline_classes),
            "borderline_max_severity": self.borderline_max_severity,
            "est_tokens_per_finding": self.est_tokens_per_finding,
        }


# ---------------------------------------------------------------------------
# Static signals
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SignalSpec:
    """One named risk signal.

    ``rule_terms`` are substrings matched (case-insensitively) against the rule id,
    message, CWE text and vulnerability class. ``code_patterns`` are regexes matched
    against the focal code snippet. A signal fires if either side matches; it is
    ``strong`` only when it matched in code, which is what feeds the source/sink check.
    """

    name: str
    weight: float
    high_risk: bool
    rule_terms: tuple = ()
    code_patterns: tuple = ()

    @property
    def weight_key(self) -> str:
        return f"signal:{self.name}"


SIGNAL_SPECS = (
    SignalSpec(
        "sql_injection", 0.25, True,
        ("sqli", "sql injection", "sql-injection", "cwe-89", "cwe-564"),
        (r"\bcreateStatement\s*\(", r"\.execute(Query|Update|Batch)?\s*\(",
         r"prepareStatement\s*\([^)]*\+", r"\bStatement\b.*\+"),
    ),
    SignalSpec(
        "command_injection", 0.30, True,
        ("command injection", "cmdi", "cwe-78", "os command"),
        (r"Runtime\.getRuntime\s*\(\s*\)\s*\.exec", r"\bProcessBuilder\b"),
    ),
    SignalSpec(
        "dynamic_execution", 0.30, True,
        ("code injection", "eval", "script engine", "cwe-94", "cwe-95", "expression language"),
        (r"\bScriptEngine\b", r"\beval\s*\(", r"Class\.forName\s*\(", r"\.invoke\s*\(",
         r"\bGroovyShell\b", r"\bExpressionFactory\b"),
    ),
    SignalSpec(
        "deserialization", 0.30, True,
        ("deserializ", "cwe-502"),
        (r"\bObjectInputStream\b", r"\breadObject\s*\(", r"\breadUnshared\s*\(",
         r"\bXMLDecoder\b", r"\bXStream\b", r"enableDefaultTyping"),
    ),
    SignalSpec(
        "path_traversal", 0.20, True,
        ("path traversal", "pathtraver", "cwe-22", "cwe-23", "cwe-73"),
        (r"new\s+File(Input|Output)?(Stream|Reader|Writer)?\s*\(", r"\bPaths\.get\s*\(",
         r"\bRandomAccessFile\b", r"\bFiles\.(read|write|newInputStream|newOutputStream)"),
    ),
    SignalSpec(
        "ldap_injection", 0.20, True,
        ("ldap", "cwe-90"),
        (r"\bInitialDirContext\b", r"\bDirContext\b", r"\bLdapContext\b"),
    ),
    SignalSpec(
        "xpath_injection", 0.20, True,
        ("xpath", "cwe-643"),
        (r"\bXPath(Factory|Expression)?\b",),
    ),
    SignalSpec(
        "xxe", 0.25, True,
        ("xxe", "xml external", "cwe-611"),
        (r"\bDocumentBuilderFactory\b", r"\bSAXParser(Factory)?\b", r"\bXMLInputFactory\b",
         r"\bXMLReader\b"),
    ),
    SignalSpec(
        "network_egress", 0.15, False,
        ("ssrf", "cwe-918", "server-side request"),
        (r"new\s+URL\s*\(", r"\.openConnection\s*\(", r"\bHttpURLConnection\b",
         r"\bHttpClient\b", r"new\s+Socket\s*\("),
    ),
    SignalSpec(
        "xss", 0.15, False,
        ("xss", "cross-site-scripting", "cross-site scripting", "cwe-79"),
        (r"getWriter\s*\(\s*\)\s*\.(print|println|write|format|append)",
         r"getOutputStream\s*\(\s*\)\s*\.(print|write)", r"\bsetHeader\s*\("),
    ),
    SignalSpec(
        "insecure_crypto", 0.10, False,
        ("crypto", "cipher", "cwe-326", "cwe-327", "cwe-330", "cwe-338", "weak random",
         "insecure random", "ecb"),
        (r"Cipher\.getInstance\s*\(\s*\"(DES|DESede|RC2|RC4|Blowfish|AES\"|AES/ECB)",
         r"/ECB/", r"\bjava\.util\.Random\b", r"new\s+Random\s*\(", r"Math\.random\s*\("),
    ),
    SignalSpec(
        "weak_hash", 0.10, False,
        ("hash", "cwe-328", "cwe-916", "md5", "sha1", "sha-1"),
        (r"MessageDigest\.getInstance\s*\(\s*\"(MD2|MD4|MD5|SHA-?1)\"",
         r"DigestUtils\.(md2|md5|sha1)"),
    ),
    SignalSpec(
        "hardcoded_secret", 0.15, False,
        ("hard-coded", "hardcoded", "secret", "credential", "cwe-798", "cwe-259", "cwe-321"),
        (r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\s*=\s*\"[^\"]{4,}\"",
         r"SecretKeySpec\s*\(\s*\""),
    ),
    SignalSpec(
        "cookie_security", 0.05, False,
        ("cookie", "cwe-614", "cwe-1004"),
        (r"new\s+Cookie\s*\(", r"setSecure\s*\(\s*false", r"setHttpOnly\s*\(\s*false"),
    ),
    SignalSpec(
        "open_redirect", 0.10, False,
        ("redirect", "cwe-601"),
        (r"\.sendRedirect\s*\(", r"setHeader\s*\(\s*\"Location\""),
    ),
    SignalSpec(
        "trust_boundary", 0.10, False,
        ("trust bound", "cwe-501"),
        (r"getSession\s*\(\s*\)\s*\.setAttribute", r"\.putValue\s*\("),
    ),
)

SIGNAL_BY_NAME = {spec.name: spec for spec in SIGNAL_SPECS}

TAINT_SOURCE_PATTERNS = (
    r"\bgetParameter(Values|Map|Names)?\s*\(",
    r"\bgetHeader(s|Names)?\s*\(",
    r"\bgetCookies\s*\(",
    r"\bgetQueryString\s*\(",
    r"\bgetRequestURI\s*\(",
    r"\bgetRequestURL\s*\(",
    r"\bgetPathInfo\s*\(",
    r"\bgetInputStream\s*\(",
    r"\bgetReader\s*\(",
    r"\bgetServletPath\s*\(",
    r"System\.getenv\s*\(",
    r"System\.getProperty\s*\(",
    r"new\s+Scanner\s*\(",
    r"\bargs\s*\[",
    r"\bgetAttribute\s*\(",
)

SANITIZER_PATTERNS = (
    r"\bESAPI\.encoder\s*\(",
    r"\bencodeFor(HTML|HTMLAttribute|JavaScript|URL|SQL|LDAP|XPath|OS)\b",
    r"\bEncode\.for\w+\s*\(",
    r"\bStringEscapeUtils\b",
    r"\bHtmlUtils\.htmlEscape\b",
    r"\bNormalizer\.normalize\b",
    r"\bURLEncoder\.encode\b",
    r"\bPattern\.matches\s*\(",
    r"\.replaceAll\s*\(\s*\"\[\^",
    r"prepareStatement\s*\([^+)]*\?",
)

_COMPILED_SIGNALS = {
    spec.name: tuple(re.compile(p) for p in spec.code_patterns) for spec in SIGNAL_SPECS
}
_COMPILED_SOURCES = tuple(re.compile(p) for p in TAINT_SOURCE_PATTERNS)
_COMPILED_SANITIZERS = tuple(re.compile(p) for p in SANITIZER_PATTERNS)
_CWE_ID_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)

_STRING_LITERAL_RE = re.compile(r'"(?:\\.|[^"\\\n])*"' + r"|'(?:\\.|[^'\\\n])'")
_LINE_COMMENT_RE = re.compile(r"//.*$")


def _brace_delta(line: str) -> int:
    """``{`` minus ``}`` on a line, ignoring string literals and ``//`` comments.

    Block comments are not tracked; BenchmarkJava keeps them out of method bodies and a
    stray miscount only widens the fallback window.
    """
    clean = _LINE_COMMENT_RE.sub("", _STRING_LITERAL_RE.sub('""', line))
    return clean.count("{") - clean.count("}")


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

@dataclass
class NormalizedFinding:
    """Flat, typed view of one Semgrep result plus its stable identity."""

    key: str
    index: int
    check_id: str
    path: str
    start_line: Optional[int]
    start_col: Optional[int]
    end_line: Optional[int]
    end_col: Optional[int]
    severity: Optional[str]
    confidence: Optional[str]
    likelihood: Optional[str]
    impact: Optional[str]
    message: str
    cwe_ids: list
    cwe_raw: list
    vulnerability_class: list
    category: Optional[str]
    subcategory: list
    technology: list
    cwe_top25: bool

    @property
    def rule_text(self) -> str:
        """Lower-cased haystack for rule-term matching."""
        parts = [self.check_id, self.message, " ".join(self.cwe_raw),
                 " ".join(self.vulnerability_class), " ".join(self.subcategory)]
        return " ".join(p for p in parts if p).lower()


def _as_int(value) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _as_upper(value) -> Optional[str]:
    if isinstance(value, str) and value.strip():
        return value.strip().upper()
    return None


def _as_str_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v is not None and str(v).strip()]
    return [str(value)]


def parse_cwe_ids(cwe_values: Iterable) -> list:
    """Extract integer CWE ids from strings like ``"CWE-89: Improper ..."``."""
    ids = []
    for value in cwe_values:
        for match in _CWE_ID_RE.finditer(str(value)):
            cwe_id = int(match.group(1))
            if cwe_id not in ids:
                ids.append(cwe_id)
    return ids


def raw_finding_key(finding: dict) -> str:
    """Identity for a finding that does not depend on list position.

    Combines the path, start position, end position and rule id. Two findings that
    share all of these are indistinguishable to us; ``normalize_findings`` suffixes
    duplicates with ``#2``, ``#3`` ... so keys stay unique within one scan.
    """
    start = finding.get("start") or {}
    end = finding.get("end") or {}
    return "{path}:{sl}:{sc}-{el}:{ec}:{rule}".format(
        path=finding.get("path") or "<no-path>",
        sl=start.get("line", "?"),
        sc=start.get("col", "?"),
        el=end.get("line", "?"),
        ec=end.get("col", "?"),
        rule=finding.get("check_id") or "<no-rule>",
    )


def normalize_finding(finding: dict, index: int, key: Optional[str] = None) -> NormalizedFinding:
    extra = finding.get("extra") or {}
    meta = extra.get("metadata") or {}
    start = finding.get("start") or {}
    end = finding.get("end") or {}
    cwe_raw = _as_str_list(meta.get("cwe"))
    return NormalizedFinding(
        key=key or raw_finding_key(finding),
        index=index,
        check_id=str(finding.get("check_id") or ""),
        path=str(finding.get("path") or ""),
        start_line=_as_int(start.get("line")),
        start_col=_as_int(start.get("col")),
        end_line=_as_int(end.get("line")),
        end_col=_as_int(end.get("col")),
        severity=_as_upper(extra.get("severity")),
        confidence=_as_upper(meta.get("confidence")),
        likelihood=_as_upper(meta.get("likelihood")),
        impact=_as_upper(meta.get("impact")),
        message=str(extra.get("message") or ""),
        cwe_ids=parse_cwe_ids(cwe_raw),
        cwe_raw=cwe_raw,
        vulnerability_class=_as_str_list(meta.get("vulnerability_class")),
        category=meta.get("category") if isinstance(meta.get("category"), str) else None,
        subcategory=_as_str_list(meta.get("subcategory")),
        technology=_as_str_list(meta.get("technology")),
        cwe_top25=bool(meta.get("cwe2022-top25") or meta.get("cwe2021-top25")),
    )


def normalize_findings(results: list) -> list:
    """Normalize every finding, assigning unique stable keys in input order."""
    seen = {}
    normalized = []
    for index, finding in enumerate(results):
        base = raw_finding_key(finding)
        count = seen.get(base, 0) + 1
        seen[base] = count
        key = base if count == 1 else f"{base}#{count}"
        normalized.append(normalize_finding(finding, index, key))
    return normalized


def missing_metadata_fields(nf: NormalizedFinding) -> list:
    """Names of metadata fields that are absent or carry unknown values."""
    missing = []
    if nf.severity not in KNOWN_SEVERITIES:
        missing.append("severity")
    if nf.confidence not in KNOWN_CONFIDENCES:
        missing.append("confidence")
    if not nf.cwe_ids:
        missing.append("cwe")
    if not nf.vulnerability_class:
        missing.append("vulnerability_class")
    if not nf.check_id:
        missing.append("check_id")
    if not nf.path:
        missing.append("path")
    if nf.start_line is None:
        missing.append("start_line")
    return missing


# ---------------------------------------------------------------------------
# Focal snippet retrieval
# ---------------------------------------------------------------------------

@dataclass
class FocalSnippet:
    status: str
    text: str = ""
    first_line: Optional[int] = None
    last_line: Optional[int] = None

    @property
    def ok(self) -> bool:
        return self.status == SNIPPET_OK

    def render(self, path: str, language: str = "java") -> str:
        if not self.ok:
            return f"### File: {path}\n<code context unavailable: {self.status}>"
        return (
            f"### File: {path}\n"
            f"Lines: {self.first_line}-{self.last_line}\n"
            f"```{language}\n{self.text}\n```"
        )


class SourceReader:
    """Reads files under a source root with caching and traversal protection."""

    def __init__(self, source_root: Optional[Path], max_bytes: int = MAX_SOURCE_FILE_BYTES):
        self.source_root = Path(source_root).resolve() if source_root else None
        self.max_bytes = max_bytes
        self._cache = {}

    def resolve(self, relative_path: str):
        """Return (resolved_path, status). Status is ``ok`` only if the path is safe."""
        if self.source_root is None:
            return None, SNIPPET_NO_SOURCE_ROOT
        if not relative_path:
            return None, SNIPPET_NO_PATH
        candidate = (self.source_root / relative_path).resolve()
        try:
            candidate.relative_to(self.source_root)
        except ValueError:
            return None, SNIPPET_OUTSIDE_ROOT
        if not candidate.is_file():
            return None, SNIPPET_FILE_NOT_FOUND
        return candidate, SNIPPET_OK

    def lines(self, relative_path: str):
        """Return (lines, status) with the file split into lines, or (None, status)."""
        resolved, status = self.resolve(relative_path)
        if status != SNIPPET_OK:
            return None, status
        cache_key = str(resolved)
        if cache_key in self._cache:
            return self._cache[cache_key]
        try:
            if resolved.stat().st_size > self.max_bytes:
                result = (None, SNIPPET_TOO_LARGE)
            else:
                text = resolved.read_text(encoding="utf-8", errors="ignore")
                result = (text.splitlines(), SNIPPET_OK)
        except OSError:
            result = (None, SNIPPET_UNREADABLE)
        self._cache[cache_key] = result
        return result

    def focal_snippet(self, relative_path: str, start_line: Optional[int],
                      end_line: Optional[int] = None, context_lines: int = 6) -> FocalSnippet:
        lines, status = self.lines(relative_path)
        if status != SNIPPET_OK:
            return FocalSnippet(status=status)
        if start_line is None or start_line < 1 or start_line > len(lines):
            return FocalSnippet(status=SNIPPET_LINE_OUT_OF_RANGE)
        last = end_line if end_line and end_line >= start_line else start_line
        last = min(last, len(lines))
        first_idx = max(0, start_line - 1 - context_lines)
        last_idx = min(len(lines), last + context_lines)
        return FocalSnippet(
            status=SNIPPET_OK,
            text="\n".join(lines[first_idx:last_idx]),
            first_line=first_idx + 1,
            last_line=last_idx,
        )

    def enclosing_method_snippet(self, relative_path: str, start_line: Optional[int],
                                 end_line: Optional[int] = None, fallback_lines: int = 40,
                                 max_method_lines: int = 400) -> FocalSnippet:
        """The method/constructor body containing ``start_line``.

        Walks up to the brace that opens the enclosing declaration (skipping control
        blocks like ``if``/``for``), then down to its matching close. Falls back to a
        +-``fallback_lines`` window when no method can be bounded or the method is larger
        than ``max_method_lines`` (keeps the small-model prompt bounded).
        """
        lines, status = self.lines(relative_path)
        if status != SNIPPET_OK:
            return FocalSnippet(status=status)
        n = len(lines)
        if start_line is None or start_line < 1 or start_line > n:
            return FocalSnippet(status=SNIPPET_LINE_OUT_OF_RANGE)

        si = start_line - 1
        open_idx = self._find_method_open(lines, si)
        if open_idx is not None:
            close_idx = self._match_close(lines, open_idx)
            if close_idx is not None and (close_idx - open_idx + 1) <= max_method_lines:
                return FocalSnippet(SNIPPET_OK, "\n".join(lines[open_idx:close_idx + 1]),
                                    open_idx + 1, close_idx + 1)

        last = end_line if end_line and end_line >= start_line else start_line
        first_idx = max(0, si - fallback_lines)
        last_idx = min(n, last + fallback_lines)
        return FocalSnippet(SNIPPET_OK, "\n".join(lines[first_idx:last_idx]), first_idx + 1, last_idx)

    @staticmethod
    def _find_method_open(lines: list, target_idx: int, max_levels: int = 8):
        """Index of the line whose unmatched ``{`` opens the method around ``target_idx``."""
        balance = 0
        for i in range(target_idx, -1, -1):
            balance += _brace_delta(lines[i])  # opens - closes
            if balance > 0:  # this line has a '{' not closed before the target
                signature = " ".join(lines[max(0, i - 2):i + 1])
                looks_like_control = any(re.search(rf"\b{kw}\b\s*[({{]", signature)
                                         for kw in CONTROL_KEYWORDS)
                looks_like_callable = "(" in signature and ")" in signature
                if looks_like_callable and not looks_like_control:
                    return i
                # keep climbing past control blocks / anonymous scopes
                balance = 0
                max_levels -= 1
                if max_levels <= 0:
                    return i if looks_like_callable else None
        return None

    @staticmethod
    def _match_close(lines: list, open_idx: int):
        depth = 0
        for i in range(open_idx, len(lines)):
            depth += _brace_delta(lines[i])
            if depth <= 0 and i > open_idx:
                return i
        return None


# ---------------------------------------------------------------------------
# Feature extraction & scoring
# ---------------------------------------------------------------------------

@dataclass
class StaticFeatures:
    signals: list                # every signal that fired (rule or code)
    code_signals: list           # signals that matched in the focal code
    high_risk_signals: list
    taint_source: bool
    source_sink_combo: bool
    sanitizer_hint: bool
    missing_metadata: list
    snippet_status: str


def extract_features(nf: NormalizedFinding, snippet: FocalSnippet,
                     wide_snippet: Optional[FocalSnippet] = None) -> StaticFeatures:
    """Signals from the focal window; taint-flow signals from the wider view when given.

    Rule/code signal detection stays on the tight window so scores are stable and
    bounded. Taint source, source->sink and sanitizer detection use ``wide_snippet``
    (the enclosing method) when available, because those rarely both land in +-6 lines.
    """
    haystack = nf.rule_text
    code = snippet.text if snippet.ok else ""
    wide = wide_snippet.text if (wide_snippet and wide_snippet.ok) else code

    signals, code_signals, high_risk = [], [], []
    for spec in SIGNAL_SPECS:
        by_rule = any(term in haystack for term in spec.rule_terms)
        by_code = bool(code) and any(rx.search(code) for rx in _COMPILED_SIGNALS[spec.name])
        if by_rule or by_code:
            signals.append(spec.name)
            if by_code:
                code_signals.append(spec.name)
            if spec.high_risk:
                high_risk.append(spec.name)

    taint_source = bool(wide) and any(rx.search(wide) for rx in _COMPILED_SOURCES)
    sanitizer = bool(wide) and any(rx.search(wide) for rx in _COMPILED_SANITIZERS)
    sink_in_wide = bool(wide) and any(
        SIGNAL_BY_NAME[spec.name].high_risk and any(rx.search(wide) for rx in _COMPILED_SIGNALS[spec.name])
        for spec in SIGNAL_SPECS
    )
    sink_in_code = sink_in_wide or any(SIGNAL_BY_NAME[name].high_risk for name in code_signals)

    return StaticFeatures(
        signals=signals,
        code_signals=code_signals,
        high_risk_signals=high_risk,
        taint_source=taint_source,
        source_sink_combo=taint_source and sink_in_code,
        sanitizer_hint=sanitizer,
        missing_metadata=missing_metadata_fields(nf),
        snippet_status=snippet.status,
    )


def score_features(nf: NormalizedFinding, features: StaticFeatures, weights: dict):
    """Return (score, breakdown). Score is clamped to [0, 1]; breakdown is per-component."""
    breakdown = {}

    def add(component: str):
        weight = weights.get(component)
        if weight:
            breakdown[component] = weight

    if nf.severity:
        add(f"severity:{nf.severity}")
    if nf.confidence:
        add(f"confidence:{nf.confidence}")
    if nf.impact:
        add(f"impact:{nf.impact}")
    if nf.likelihood:
        add(f"likelihood:{nf.likelihood}")
    if nf.cwe_top25:
        add("cwe_top25")
    for sub in nf.subcategory:
        add(f"subcategory:{sub.lower()}")
    for name in features.signals:
        add(f"signal:{name}")
    if features.taint_source:
        add("taint_source")
    if features.source_sink_combo:
        add("source_sink_combo")
    if features.sanitizer_hint:
        add("sanitizer_hint")
    if features.missing_metadata:
        add("missing_metadata")
    if features.snippet_status != SNIPPET_OK:
        add("missing_context")

    score = max(0.0, min(1.0, sum(breakdown.values())))
    return round(score, 4), breakdown


def score_band(score: float, thresholds: dict) -> str:
    if score >= thresholds["escalate_at"]:
        return BAND_HIGH
    if score >= thresholds["borderline_at"]:
        return BAND_MEDIUM
    return BAND_LOW


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

@dataclass
class TriageDecision:
    key: str
    index: int
    action: str
    score: float
    band: str
    hard_guards: list
    reasons: list
    signals: list
    code_signals: list
    high_risk_signals: list
    taint_source: bool
    source_sink_combo: bool
    sanitizer_hint: bool
    missing_metadata: list
    snippet_status: str
    snippet_lines: Optional[list]
    score_breakdown: dict
    focal_code: str = field(default="", repr=False)       # tight window used for scoring
    screen_code: str = field(default="", repr=False)      # enclosing method, for the small model
    method_lines: Optional[list] = None
    small_model: Optional[dict] = None

    @property
    def retained(self) -> bool:
        """True when the finding still needs a model (robust or small) to look at it."""
        return self.action != ACTION_DEFER

    def to_dict(self, include_focal_code: bool = False) -> dict:
        data = {
            "key": self.key,
            "action": self.action,
            "score": self.score,
            "band": self.band,
            "hard_guards": list(self.hard_guards),
            "reasons": list(self.reasons),
            "signals": list(self.signals),
            "code_signals": list(self.code_signals),
            "high_risk_signals": list(self.high_risk_signals),
            "taint_source": self.taint_source,
            "source_sink_combo": self.source_sink_combo,
            "sanitizer_hint": self.sanitizer_hint,
            "missing_metadata": list(self.missing_metadata),
            "snippet_status": self.snippet_status,
            "snippet_lines": list(self.snippet_lines) if self.snippet_lines else None,
            "method_lines": list(self.method_lines) if self.method_lines else None,
            "score_breakdown": dict(self.score_breakdown),
        }
        if self.small_model is not None:
            data["small_model"] = dict(self.small_model)
        if include_focal_code:
            data["focal_code"] = self.focal_code
            data["screen_code"] = self.screen_code
        return data

    def evidence_summary(self) -> str:
        """Compact human/LLM readable summary of the static evidence."""
        parts = [f"static_score={self.score:.2f} band={self.band}"]
        if self.hard_guards:
            parts.append("guards=" + ",".join(self.hard_guards))
        if self.signals:
            parts.append("signals=" + ",".join(self.signals))
        if self.code_signals:
            parts.append("in_code=" + ",".join(self.code_signals))
        if self.taint_source:
            parts.append("taint_source_in_method=yes")
        if self.source_sink_combo:
            parts.append("source_sink_combo=yes")
        else:
            parts.append("source_sink_combo=not_seen")
        if self.sanitizer_hint:
            parts.append("sanitizer_call_in_method=yes")
        if self.missing_metadata:
            parts.append("missing_metadata=" + ",".join(self.missing_metadata))
        if self.snippet_status != SNIPPET_OK:
            parts.append(f"code_context={self.snippet_status}")
        if self.small_model:
            parts.append(
                f"small_model={self.small_model.get('decision')}"
                + (f" ({self.small_model.get('reason')})" if self.small_model.get("reason") else "")
            )
        return "; ".join(parts)


def _active_guards(nf: NormalizedFinding, features: StaticFeatures, guards: dict) -> list:
    active = []
    if guards.get(GUARD_SEVERITY_ERROR) and nf.severity == "ERROR":
        active.append(GUARD_SEVERITY_ERROR)
    if guards.get(GUARD_SEVERITY_WARNING) and nf.severity == "WARNING":
        active.append(GUARD_SEVERITY_WARNING)
    if guards.get(GUARD_MISSING_METADATA) and features.missing_metadata:
        active.append(GUARD_MISSING_METADATA)
    if guards.get(GUARD_MISSING_CONTEXT) and features.snippet_status != SNIPPET_OK:
        active.append(GUARD_MISSING_CONTEXT)
    if guards.get(GUARD_HIGH_RISK_SIGNAL) and features.high_risk_signals:
        active.append(GUARD_HIGH_RISK_SIGNAL)
    return active


def _class_is_borderline_eligible(nf: NormalizedFinding, settings: TriageSettings) -> bool:
    cls = " ".join(nf.vulnerability_class).lower()
    return any(frag in cls for frag in settings.borderline_classes)


def _borderline_filters_pass(nf: NormalizedFinding, settings: TriageSettings) -> bool:
    """Severity/confidence gate shared by both borderline routes."""
    if nf.confidence == "HIGH":
        return False
    return SEVERITY_RANK.get(nf.severity, 1) <= SEVERITY_RANK.get(settings.borderline_max_severity, 2)


def _is_borderline_candidate(nf: NormalizedFinding, features: StaticFeatures,
                             settings: TriageSettings, score: float) -> bool:
    """True when the finding's class is false-positive-prone and it clears the filters.

    On this benchmark no local feature separates a real injection bug from a sanitized
    one, so class membership (not a taint-flow heuristic) decides eligibility and the
    small model does the actual judging. The score-band route is handled in ``decide``
    and only applies when no guard fires.
    """
    return _class_is_borderline_eligible(nf, settings) and _borderline_filters_pass(nf, settings)


def decide(nf: NormalizedFinding, snippet: FocalSnippet, settings: TriageSettings,
           allow_borderline: bool = True, wide_snippet: Optional[FocalSnippet] = None) -> TriageDecision:
    """Produce the Layer-1 decision for one normalized finding."""
    features = extract_features(nf, snippet, wide_snippet)
    weights = settings.effective_weights()
    score, breakdown = score_features(nf, features, weights)
    band = score_band(score, settings.thresholds)
    guards = _active_guards(nf, features, settings.guards)
    reasons = []

    class_eligible = _class_is_borderline_eligible(nf, settings)
    class_borderline = class_eligible and _borderline_filters_pass(nf, settings)

    # Absolute escalations override borderline routing. A confirmed source->sink flow
    # forces escalation only for classes that are NOT small-model-eligible (e.g.
    # deserialization, XXE) — for injection families the small model is meant to judge
    # exactly those, since almost every Benchmark method has a source and a sink.
    absolute = [g for g in (GUARD_MISSING_METADATA, GUARD_MISSING_CONTEXT) if g in guards]
    if features.source_sink_combo and not class_eligible:
        absolute.append("source_sink_combo")

    score_borderline = (not guards and not absolute
                        and settings.thresholds["borderline_at"] <= score < settings.thresholds["escalate_at"])

    if absolute:
        action = ACTION_ESCALATE
        reasons.extend(f"guard:{g}" for g in absolute)
    elif allow_borderline and class_borderline:
        action = ACTION_BORDERLINE
        reasons.append("class_borderline")
    elif class_borderline:  # eligible but small model is off
        action = ACTION_ESCALATE
        reasons.extend(f"guard:{g}" for g in guards)
        reasons.append("small_model_disabled")
    elif guards:
        action = ACTION_ESCALATE
        reasons.extend(f"guard:{g}" for g in guards)
    elif score >= settings.thresholds["escalate_at"]:
        action = ACTION_ESCALATE
        reasons.append("score_at_or_above_escalate_threshold")
    elif score_borderline:
        action = ACTION_BORDERLINE if allow_borderline else ACTION_ESCALATE
        reasons.append("score_in_borderline_band" if allow_borderline
                       else "score_in_borderline_band_small_model_disabled")
    else:
        action = ACTION_DEFER
        reasons.append("score_below_borderline_threshold_no_guards")

    method_ok = wide_snippet is not None and wide_snippet.ok
    return TriageDecision(
        key=nf.key,
        index=nf.index,
        action=action,
        score=score,
        band=band,
        hard_guards=guards,
        reasons=reasons,
        signals=features.signals,
        code_signals=features.code_signals,
        high_risk_signals=features.high_risk_signals,
        taint_source=features.taint_source,
        source_sink_combo=features.source_sink_combo,
        sanitizer_hint=features.sanitizer_hint,
        missing_metadata=features.missing_metadata,
        snippet_status=snippet.status,
        snippet_lines=[snippet.first_line, snippet.last_line] if snippet.ok else None,
        method_lines=[wide_snippet.first_line, wide_snippet.last_line] if method_ok else None,
        score_breakdown=breakdown,
        focal_code=snippet.text if snippet.ok else "",
        screen_code=wide_snippet.text if method_ok else (snippet.text if snippet.ok else ""),
    )


# ---------------------------------------------------------------------------
# Batch run & aggregate metrics
# ---------------------------------------------------------------------------

@dataclass
class TriageRun:
    normalized: list
    decisions: list
    elapsed_seconds: float
    settings: TriageSettings

    def by_action(self, action: str) -> list:
        return [d for d in self.decisions if d.action == action]

    def indices(self, action: str) -> list:
        return [d.index for d in self.decisions if d.action == action]


def run_triage(results: list, source_root: Optional[Path], settings: Optional[TriageSettings] = None,
               allow_borderline: bool = True, reader: Optional[SourceReader] = None) -> TriageRun:
    """Run Layer-1 triage over every finding, preserving input order."""
    settings = settings or TriageSettings()
    reader = reader or SourceReader(source_root)
    t0 = time.time()
    normalized = normalize_findings(results)
    decisions = []
    for nf in normalized:
        snippet = reader.focal_snippet(nf.path, nf.start_line, nf.end_line, settings.context_lines)
        method = reader.enclosing_method_snippet(
            nf.path, nf.start_line, nf.end_line,
            settings.method_context_fallback_lines, settings.max_method_lines)
        decisions.append(decide(nf, snippet, settings, allow_borderline=allow_borderline,
                                wide_snippet=method))
    return TriageRun(normalized=normalized, decisions=decisions,
                     elapsed_seconds=time.time() - t0, settings=settings)


def summarize_decisions(decisions: list, settings: TriageSettings, batch_size: int,
                        elapsed_seconds: Optional[float] = None) -> dict:
    """Aggregate metrics used by ``triage_report.json`` and the calibration report."""
    total = len(decisions)
    counts = {action: 0 for action in ACTIONS}
    bands = {BAND_HIGH: 0, BAND_MEDIUM: 0, BAND_LOW: 0}
    guard_counts = {}
    signal_counts = {}
    reason_counts = {}
    snippet_status = {}
    small_model = {}
    histogram = [0] * 10

    for d in decisions:
        counts[d.action] = counts.get(d.action, 0) + 1
        bands[d.band] = bands.get(d.band, 0) + 1
        for g in d.hard_guards:
            guard_counts[g] = guard_counts.get(g, 0) + 1
        for s in d.signals:
            signal_counts[s] = signal_counts.get(s, 0) + 1
        for r in d.reasons:
            reason_counts[r] = reason_counts.get(r, 0) + 1
        snippet_status[d.snippet_status] = snippet_status.get(d.snippet_status, 0) + 1
        if d.small_model:
            decision = d.small_model.get("decision", "unknown")
            small_model[decision] = small_model.get(decision, 0) + 1
        histogram[min(9, int(d.score * 10))] += 1

    deferred = counts[ACTION_DEFER]
    retained = total - deferred
    deep_calls_total = math.ceil(total / batch_size) if batch_size else 0
    deep_calls_after = math.ceil(retained / batch_size) if batch_size else 0

    return {
        "total_findings": total,
        "counts": counts,
        "escalation_rate": round(retained / total, 4) if total else 0.0,
        "deferral_rate": round(deferred / total, 4) if total else 0.0,
        "score_bands": bands,
        "score_histogram": {f"{i/10:.1f}-{(i+1)/10:.1f}": n for i, n in enumerate(histogram)},
        "hard_guards": guard_counts,
        "signals": signal_counts,
        "reasons": reason_counts,
        "snippet_status": snippet_status,
        "small_model_decisions": small_model,
        "timing_seconds": round(elapsed_seconds, 3) if elapsed_seconds is not None else None,
        "estimated_savings": {
            "deep_model_findings_avoided": deferred,
            "deep_model_calls_baseline": deep_calls_total,
            "deep_model_calls_after_triage": deep_calls_after,
            "deep_model_calls_avoided": deep_calls_total - deep_calls_after,
            "tokens_avoided": deferred * settings.est_tokens_per_finding,
            "tokens_per_finding_assumed": settings.est_tokens_per_finding,
        },
        "thresholds": dict(settings.thresholds),
        "guards": dict(settings.guards),
    }
