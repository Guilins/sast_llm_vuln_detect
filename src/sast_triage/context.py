"""Code context for the robust prompt.

Two jobs: (1) resolve the project/helper methods a finding's method calls and inline
their bodies (``ProjectIndex`` etc.), so the model can see a sanitizer that lives in
another file; (2) assemble the per-batch prompt (slim findings + method snippets +
cross-file context + static evidence).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage

from .config import PipelineConfig
from .json_repair import _normalize_llm_content
from .prompts import SYSTEM_PROMPT_TEMPLATE
from .triage import SourceReader


# ==================================================================
# Cross-file resolution
#
# Uses a real Java grammar (tree-sitter) rather than pattern matching: method/class
# boundaries, generics, multi-line signatures and comments all fall out of the parse
# for free, and — the thing regex genuinely could not do — an unqualified call inside a
# method (``helper(x)``, no receiver) resolves against the method's own enclosing class,
# not just receiver-qualified calls (``x.helper()``).
# ==================================================================


def _require_java_parser():
    try:
        import tree_sitter_java as _tsjava
        from tree_sitter import Language, Parser
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "Cross-file context resolution needs a Java parser. Install it with:\n"
            "  python -m pip install tree-sitter tree-sitter-java"
        ) from exc
    return Parser(Language(_tsjava.language()))


_JAVA_BUILTINS = {
    "String", "Integer", "Long", "Boolean", "Object", "Math", "System", "Arrays",
    "List", "Map", "Set", "HashMap", "ArrayList", "StringBuilder", "StringBuffer",
    "Exception", "Thread", "Class", "Character", "Double", "Float", "Byte",
}

_TYPE_DECL_NODES = ("class_declaration", "interface_declaration", "enum_declaration",
                    "record_declaration")
_METHOD_NODES = ("method_declaration", "constructor_declaration")
_BINDING_NODES = ("local_variable_declaration", "field_declaration", "formal_parameter")


def _wrap(text: str) -> bytes:
    """A bare method/snippet isn't a valid compilation unit on its own; wrapping it in a
    throwaway class lets the parser treat it as one without touching its own coordinates
    (nothing here slices text back out by byte offset, so the wrapper needs no unwinding)."""
    return ("class __CrossFileWrapper__ {\n" + text + "\n}").encode("utf-8", "replace")


def _child_of_type(node, type_name):
    for c in node.children:
        if c.type == type_name:
            return c
    return None


def _text(node) -> str:
    return node.text.decode("utf-8", "replace")


def _simple_type_name(type_node):
    """Best-effort unqualified class name for a type node; None for primitives, wildcards
    and other types that can never be a project class anyway."""
    if type_node is None:
        return None
    t = type_node.type
    if t in ("type_identifier", "identifier"):
        return _text(type_node)
    if t == "generic_type":
        return _simple_type_name(type_node.children[0]) if type_node.child_count else None
    if t == "scoped_type_identifier":
        last = type_node.children[-1] if type_node.child_count else None
        return _simple_type_name(last) if last is not None else None
    if t == "array_type":
        return _simple_type_name(type_node.child_by_field_name("element"))
    return None  # primitive_type, void_type, wildcard, ...


def _walk_type_declarations(node):
    """Every class/interface/enum/record declaration in the tree, at any nesting depth."""
    if node.type in _TYPE_DECL_NODES:
        yield node
    for c in node.children:
        yield from _walk_type_declarations(c)


def _iter_method_invocations(node):
    if node.type == "method_invocation":
        yield node
    for c in node.children:
        yield from _iter_method_invocations(c)


def _type_name(type_decl_node):
    name_node = type_decl_node.child_by_field_name("name")
    return _text(name_node) if name_node is not None else None


def _supertypes_of(type_decl_node) -> list:
    names = []
    superclass = type_decl_node.child_by_field_name("superclass")
    if superclass is not None and superclass.child_count:
        name = _simple_type_name(superclass.children[-1])
        if name:
            names.append(name)
    interfaces = (type_decl_node.child_by_field_name("interfaces")
                 or _child_of_type(type_decl_node, "extends_interfaces"))
    if interfaces is not None:
        type_list = _child_of_type(interfaces, "type_list")
        if type_list is not None:
            for c in type_list.children:
                name = _simple_type_name(c)
                if name:
                    names.append(name)
    return names


def _direct_methods(type_decl_node):
    body = type_decl_node.child_by_field_name("body")
    if body is None:
        return
    for c in body.children:
        if c.type in _METHOD_NODES:
            yield c


def _class_name_at_offset(tree_root, offset: int):
    """The innermost class/interface/enum whose source range contains ``offset``."""
    best = None
    for type_node in _walk_type_declarations(tree_root):
        if type_node.start_byte <= offset < type_node.end_byte:
            best = type_node
    return _type_name(best) if best is not None else None


def _collect_type_bindings(node, out: dict) -> None:
    """var/param/field name -> simple class name, from every declaration in the subtree.

    Not scope-precise (a field and a same-named local both just land in the same dict,
    last one wins) — matching what this needs it for: a best-effort guess at a receiver's
    type, not a real symbol table.
    """
    if node.type in ("local_variable_declaration", "field_declaration"):
        simple = _simple_type_name(node.child_by_field_name("type"))
        if simple:
            for c in node.children:
                if c.type == "variable_declarator":
                    name_node = c.child_by_field_name("name")
                    if name_node is not None:
                        out[_text(name_node)] = simple
    elif node.type == "formal_parameter":
        simple = _simple_type_name(node.child_by_field_name("type"))
        name_node = node.child_by_field_name("name")
        if simple and name_node is not None:
            out[_text(name_node)] = simple
    for c in node.children:
        _collect_type_bindings(c, out)


def _call_receiver_and_name(call_node):
    """(kind, receiver_name_or_None, method_name) for one ``method_invocation`` node.

    ``kind`` is ``"none"`` (bare call, no receiver), ``"this"``, ``"identifier"``, or
    ``"chain"`` for anything else (a field access chain's leaf identifier is resolved;
    a receiver that is itself a call, e.g. ``getConn().createStatement()``, is left
    unresolved here — the inner call is still visited on its own since the walk covers
    every ``method_invocation`` node, nested or not)."""
    name_node = call_node.child_by_field_name("name")
    if name_node is None:
        return None
    method_name = _text(name_node)
    obj = call_node.child_by_field_name("object")
    if obj is None:
        return "none", None, method_name
    if obj.type == "this":
        return "this", None, method_name
    if obj.type == "identifier":
        return "identifier", _text(obj), method_name
    if obj.type == "field_access":
        field_node = obj.child_by_field_name("field")
        if field_node is not None:
            return "identifier", _text(field_node), method_name
    return "chain", None, method_name


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
                source_bytes = path.read_bytes()
            except OSError:
                continue
            try:
                tree = _require_java_parser().parse(source_bytes)
            except Exception:
                continue  # unparseable file: skip it, same as a regex that never matched
            for type_node in _walk_type_declarations(tree.root_node):
                class_name = _type_name(type_node)
                if not class_name:
                    continue
                idx.class_files.setdefault(class_name, str(path))
                for sup in _supertypes_of(type_node):
                    idx.supertypes.setdefault(class_name, []).append(sup)
                    idx.subtypes.setdefault(sup, []).append(class_name)
                for m in _direct_methods(type_node):
                    if m.child_by_field_name("body") is None:
                        continue  # abstract/interface method: no body to inline
                    name_node = m.child_by_field_name("name")
                    if name_node is None:
                        continue
                    body_text = source_bytes[m.start_byte:m.end_byte].decode("utf-8", "replace")
                    sig_line = body_text.split("\n", 1)[0].strip()
                    md = MethodDef(class_name, _text(name_node), sig_line, body_text)
                    idx.methods.setdefault(class_name, {}).setdefault(md.name, []).append(md)
        return idx

    def lookup(self, class_name: str, method_name: str) -> list:
        """All method bodies for ``class_name.method_name``, including implementors when
        ``class_name`` is an interface/abstract type that is called polymorphically."""
        found = list(self.methods.get(class_name, {}).get(method_name, []))
        for impl in self.subtypes.get(class_name, []):
            found.extend(self.methods.get(impl, {}).get(method_name, []))
        return found


def _resolve_types(enclosing_file_text: str, focal_method: str) -> dict:
    """var/param/field name -> simple class name, from the whole enclosing file plus the
    focal method (parsed standalone, in case it isn't a verbatim substring of the file,
    e.g. a hand-built snippet in a test)."""
    out = {}
    try:
        tree = _require_java_parser().parse(enclosing_file_text.encode("utf-8", "replace"))
        _collect_type_bindings(tree.root_node, out)
    except Exception:
        pass
    try:
        tree = _require_java_parser().parse(_wrap(focal_method))
        _collect_type_bindings(tree.root_node, out)
    except Exception:
        pass
    return out


def expand_calls(focal_method: str, enclosing_file_text: str, index: ProjectIndex,
                 max_methods: int = 8, max_chars: int = 3200, depth: int = 2) -> list:
    """Return ``[(label, body), ...]`` for project methods the focal method calls.

    ``enclosing_file_text`` is used to resolve receiver-variable types and the focal
    method's own enclosing class (needed to resolve unqualified calls). Expansion
    recurses ``depth`` levels (a helper that calls another helper) and stops at the caps.
    """
    types = _resolve_types(enclosing_file_text, focal_method)

    focal_class = None
    try:
        file_tree = _require_java_parser().parse(enclosing_file_text.encode("utf-8", "replace"))
        offset = enclosing_file_text.find(focal_method)
        if offset >= 0:
            focal_class = _class_name_at_offset(file_tree.root_node, offset)
    except Exception:
        pass

    out, seen, budget = [], set(), max_chars
    frontier = [(focal_method, focal_class, depth)]

    while frontier and len(out) < max_methods and budget > 0:
        text, current_class, d = frontier.pop(0)
        if d <= 0:
            continue
        try:
            tree = _require_java_parser().parse(_wrap(text))
        except Exception:
            continue
        for call_node in _iter_method_invocations(tree.root_node):
            info = _call_receiver_and_name(call_node)
            if info is None:
                continue
            kind, recv, method = info
            if kind == "chain":
                continue
            cls = current_class if kind in ("none", "this") else (
                recv if recv[:1].isupper() else types.get(recv))
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
                frontier.append((md.body, md.class_name, d - 1))
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

