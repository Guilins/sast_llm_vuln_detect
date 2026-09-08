"""Code context for the robust prompt.

Two jobs: (1) resolve the project/helper methods a finding's method calls and inline
their bodies (``ProjectIndex`` etc.), so the model can see a sanitizer that lives in
another file; (2) assemble the per-batch prompt (slim findings + method snippets +
cross-file context + static evidence).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage

from .config import PipelineConfig
from .json_repair import _normalize_llm_content
from .prompts import SYSTEM_PROMPT_TEMPLATE
from .triage import SourceReader


# ==================================================================
# Cross-file resolution
# ==================================================================


# Start of a Java method: modifiers, return type, name, "(".  The parameter list and
# the opening brace may be on later lines, so this matches only up to "(" and the caller
# scans ahead for the "{".
_METHOD_START = re.compile(
    r"^[ \t]+(?:@\w+(?:\([^)]*\))?\s+)*"
    r"(?:(?:public|private|protected|static|final|synchronized|abstract|native|default)\s+)+"
    r"(?:<[^>]+>\s+)?"
    r"(?P<ret>[A-Za-z_][\w.<>\[\], ?]*)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*\("
)
_CLASS_DECL = re.compile(r"\b(?:class|interface|enum)\s+([A-Z]\w*)\b(?P<rest>[^{]*)")
_IMPLEMENTS = re.compile(r"\b(?:implements|extends)\s+([A-Za-z_][\w., <>]*)")
_CTOR_HINT = re.compile(r"\bnew\s+([A-Z]\w*)\s*\(")
# `Type var` / `Type var =` / `Type var;`  (Type may be dotted / generic)
_VAR_DECL = re.compile(r"\b([A-Za-z_][\w.]*(?:<[^>;]*>)?)\s+([a-z_]\w*)\s*[=;)]")
# `Recv.method(`  — Recv is a var name or a ClassName
_CALL = re.compile(r"\b([A-Za-z_]\w*)\.([a-z_]\w*)\s*\(")
_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)

_JAVA_BUILTINS = {
    "String", "Integer", "Long", "Boolean", "Object", "Math", "System", "Arrays",
    "List", "Map", "Set", "HashMap", "ArrayList", "StringBuilder", "StringBuffer",
    "Exception", "Thread", "Class", "Character", "Double", "Float", "Byte",
}


def _strip_comments(text: str) -> str:
    return _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub("", text))


def _match_brace_end(lines: list, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(lines)):
        s = _LINE_COMMENT.sub("", lines[i])
        depth += s.count("{") - s.count("}")
        if depth <= 0 and i > open_idx:
            return i
        if depth <= 0 and "{" in s and "}" in s:
            return i
    return min(open_idx + 60, len(lines) - 1)


@dataclass
class MethodDef:
    class_name: str
    name: str
    signature: str
    body: str


@dataclass
class ProjectIndex:
    """``ClassName -> {methodName -> [MethodDef]}`` plus supertype links."""

    methods: dict = field(default_factory=dict)
    class_files: dict = field(default_factory=dict)
    supertypes: dict = field(default_factory=dict)     # class -> [interfaces/superclasses]
    subtypes: dict = field(default_factory=dict)       # interface/superclass -> [implementors]

    @classmethod
    def build(cls, source_root, max_files: int = 20000) -> "ProjectIndex":
        idx = cls()
        root = Path(source_root)
        if not root.is_dir():
            return idx
        for n, path in enumerate(sorted(root.rglob("*.java"))):
            if n >= max_files:
                break
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            current_class = None
            for i, line in enumerate(lines):
                cm = _CLASS_DECL.search(line)
                if cm:
                    current_class = cm.group(1)
                    idx.class_files.setdefault(current_class, str(path))
                    im = _IMPLEMENTS.search(cm.group("rest"))
                    if im:
                        for sup in re.split(r"[,\s]+", im.group(1).strip()):
                            sup = sup.split("<")[0].strip()
                            if sup and sup[0].isupper():
                                idx.supertypes.setdefault(current_class, []).append(sup)
                                idx.subtypes.setdefault(sup, []).append(current_class)
                    continue
                if not current_class:
                    continue
                ms = _METHOD_START.match(line)
                if not ms or ms.group("name") in ("if", "for", "while", "switch", "catch", "return", "new"):
                    continue
                # find the "{" that opens the body (this line or the next few)
                open_idx = None
                for j in range(i, min(i + 4, len(lines))):
                    if ";" in _LINE_COMMENT.sub("", lines[j]).split("{")[0] and "{" not in lines[j]:
                        break  # abstract/interface method declaration, no body
                    if "{" in lines[j]:
                        open_idx = j
                        break
                if open_idx is None:
                    continue
                end = _match_brace_end(lines, open_idx)
                body = "\n".join(lines[i:end + 1])
                md = MethodDef(current_class, ms.group("name"), lines[i].strip(), body)
                idx.methods.setdefault(current_class, {}).setdefault(md.name, []).append(md)
        return idx

    def lookup(self, class_name: str, method_name: str) -> list:
        """All method bodies for ``class_name.method_name``, including implementors when
        ``class_name`` is an interface/abstract type that is called polymorphically."""
        found = list(self.methods.get(class_name, {}).get(method_name, []))
        for impl in self.subtypes.get(class_name, []):
            found.extend(self.methods.get(impl, {}).get(method_name, []))
        return found


def _resolve_types(scope_text: str) -> dict:
    """var name -> simple class name, from declarations/params/`new` in the scope."""
    types = {}
    clean = _strip_comments(scope_text)
    for typ, var in _VAR_DECL.findall(clean):
        simple = typ.split(".")[-1].split("<")[0]
        if simple and simple[0].isupper():
            types[var] = simple
    return types


def expand_calls(focal_method: str, enclosing_file_text: str, index: ProjectIndex,
                 max_methods: int = 8, max_chars: int = 3200, depth: int = 2) -> list:
    """Return ``[(label, body), ...]`` for project methods the focal method calls.

    ``enclosing_file_text`` is used to resolve receiver-variable types. Expansion recurses
    ``depth`` levels (a helper that calls another helper) and stops at the caps.
    """
    types = _resolve_types(enclosing_file_text + "\n" + focal_method)
    out, seen, budget = [], set(), max_chars
    frontier = [(_strip_comments(focal_method), depth)]

    while frontier and len(out) < max_methods and budget > 0:
        text, d = frontier.pop(0)
        if d <= 0:
            continue
        for recv, method in _CALL.findall(text):
            cls = recv if recv[0].isupper() else types.get(recv)
            if not cls or cls in _JAVA_BUILTINS:
                continue
            for md in index.lookup(cls, method):
                key = (md.class_name, md.name)
                if key in seen:
                    continue
                seen.add(key)
                if len(md.body) > budget or len(out) >= max_methods:
                    continue
                out.append((f"{md.class_name}.{md.name}", md.body))
                budget -= len(md.body)
                frontier.append((_strip_comments(md.body), d - 1))
    return out


def render_cross_file(focal_method: str, enclosing_file_text: str, index: ProjectIndex,
                      **kw) -> str:
    blocks = expand_calls(focal_method, enclosing_file_text, index, **kw)
    if not blocks:
        return ""
    parts = ["### Called project methods (bodies):"]
    for label, body in blocks:
        parts.append(f"# {label}\n{body}")
    return "\n\n".join(parts)


# ==================================================================
# Per-batch prompt assembly
# ==================================================================

def read_code_snippet(repo_root, relative_path, line_number, context_lines=6):
    """Read a code snippet around a specific line in a file."""
    reader = SourceReader(repo_root)
    snippet = reader.focal_snippet(relative_path, line_number, None, context_lines)
    if snippet.status == "file_not_found":
        return f"File not found: {relative_path}"
    if not snippet.ok:
        return f"Unable to read file: {relative_path} ({snippet.status})"
    extension = Path(relative_path).suffix.lstrip('.') or 'txt'
    return snippet.render(relative_path, extension)


def build_batch_context(batch_findings, repo_root, context_lines=6, reader=None,
                        method_context=True, method_fallback_lines=40, project_index=None):
    """Build the code-context section for a batch of SAST findings.

    With ``method_context`` (the default), each finding gets its enclosing method
    (brace-matched). With ``project_index`` (a ``code_context.ProjectIndex``), the bodies
    of the project methods that method calls are appended too, so the model can see the
    sanitizer/source when it lives in a helper class in another file.
    """
    reader = reader or SourceReader(repo_root)
    snippets = []
    seen = set()

    for finding in batch_findings:
        path = finding.get("path")
        line = (finding.get("start") or {}).get("line") or finding.get("line")
        if not path:
            continue
        end_line = (finding.get("end") or {}).get("line")

        if method_context:
            snippet = reader.enclosing_method_snippet(path, line, end_line, method_fallback_lines)
        else:
            snippet = reader.focal_snippet(path, line, end_line, context_lines)

        if snippet.status == "file_not_found":
            if path not in seen:
                seen.add(path)
                snippets.append(f"File not found: {path}")
            continue
        if not snippet.ok:
            continue

        key = (path, snippet.first_line, snippet.last_line)
        if key in seen:
            continue
        seen.add(key)
        ext = Path(path).suffix.lstrip('.') or 'txt'
        block = snippet.render(path, ext)

        if project_index is not None:
            file_lines, status = reader.lines(path)
            if status == "ok":
                cross = render_cross_file(snippet.text, "\n".join(file_lines), project_index)
                if cross:
                    block += "\n\n" + cross
        snippets.append(block)

    return "\n\n".join(snippets) if snippets else "No relevant code context available."


# Kept for callers that used the older name.


build_batch_context_cached = build_batch_context


def slim_finding(finding):
    """Extract only the fields the LLM needs for analysis (halves token count)."""
    extra = finding.get("extra", {})
    meta = extra.get("metadata", {})
    return {
        "check_id": finding.get("check_id"),
        "path": finding.get("path"),
        "start": {"line": finding.get("start", {}).get("line")},
        "end": {"line": finding.get("end", {}).get("line")},
        "message": extra.get("message", ""),
        "severity": extra.get("severity", ""),
        "cwe": meta.get("cwe", []),
        "confidence": meta.get("confidence"),
        "vulnerability_class": meta.get("vulnerability_class", []),
    }


def format_triage_evidence(evidence_lines):
    """Render per-finding evidence as a numbered block for the robust prompt."""
    if not evidence_lines:
        return "No static evidence available."
    return "\n".join(f"[{i}] {line}" for i, line in enumerate(evidence_lines, 1))


def _reformat_non_json_response(llm, raw_response, expected_count):
    """Ask the LLM to convert plain-text analysis into strict JSON."""
    response = llm.invoke([
        SystemMessage(content=(
            "You are a JSON formatter. Convert the provided analysis into a valid JSON array. "
            "Output ONLY JSON with no markdown or extra text."
        )),
        HumanMessage(content=(
            f"Convert this analysis into a JSON array with exactly {expected_count} items. "
            "Each item should represent one finding and keep the original order whenever possible.\n\n"
            f"ANALYSIS:\n{raw_response}"
        )),
    ])
    return _normalize_llm_content(response.content)


def extract_findings_from_parsed(parsed):
    """
    Extract a flat list of finding dicts from various LLM output structures.
    Handles: list, dict with "results", dict with "findings", nested results.
    """
    if isinstance(parsed, list):
        flat = []
        for item in parsed:
            if isinstance(item, dict) and "results" in item and isinstance(item["results"], list):
                flat.extend(item["results"])
            else:
                flat.append(item)
        return flat

    if isinstance(parsed, dict):
        for key in ("results", "findings", "vulnerabilities"):
            if key in parsed and isinstance(parsed[key], list):
                return extract_findings_from_parsed(parsed[key])

    return None


# ---------------------------------------------------------------------------
# Progress / resume helpers
# ---------------------------------------------------------------------------


def build_batch_messages(batch, reader, config: PipelineConfig, evidence_lines=None):
    """Construct the (system, human) message pair for one robust-analysis batch.

    The system message is the stable instruction block (caches across batches); the
    human message carries the per-batch findings, code and pre-screen evidence.
    """
    slim_batch = [slim_finding(f) for f in batch]
    code_context = build_batch_context(
        batch, config.source_root, config.triage.context_lines, reader,
        method_context=True,
        method_fallback_lines=config.triage.method_context_fallback_lines,
        project_index=getattr(reader, "project_index", None))

    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
        num_findings=len(batch),
        sast_output=json.dumps({"results": slim_batch}),
        context=code_context,
        triage_evidence=format_triage_evidence(evidence_lines),
    )
    return [
        SystemMessage(content=system_prompt),
        HumanMessage(content=(
            f"Analyze ALL {len(batch)} findings and output ONLY a JSON array "
            f"of exactly {len(batch)} objects — one per finding, same order. "
            "No markdown, no text outside the JSON."
        )),
    ]

