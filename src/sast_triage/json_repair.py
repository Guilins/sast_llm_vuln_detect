"""JSON repair utilities for parsing malformed LLM output."""

import json
import re


def _normalize_llm_content(content):
    """Normalize model content into a plain string."""
    if content is None:
        return ""
    if isinstance(content, str):
        content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL).strip()
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text") or item.get("content") or ""
                if text:
                    parts.append(str(text))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return str(content)


def _strip_fences_and_locate(raw):
    """Strip markdown code fences and trailing LLM tokens, locate first JSON bracket."""
    content = _normalize_llm_content(raw).strip()
    if not content:
        return None

    # Prefer explicit fenced JSON blocks if present.
    fenced = re.findall(r"```(?:json)?\s*([\s\S]*?)```", content, flags=re.IGNORECASE)
    for block in fenced:
        block = block.strip()
        if any(ch in block for ch in "[{"):
            content = block
            break

    content = re.sub(r'^```(?:json)?\s*', '', content)
    content = re.sub(r'\s*```\s*$', '', content)
    content = re.sub(r'<\|endoftext\|>.*', '', content, flags=re.DOTALL)
    content = content.strip()
    for idx, ch in enumerate(content):
        if ch in '[{':
            return content[idx:]
    return None


def _fix_invalid_escapes(content):
    """Fix escape sequences that are invalid in JSON (e.g. \\' -> ')."""
    return re.sub(r"""\\(?!["\\\/bfnrtu])""", '', content)


def _try_parse(content):
    """Try json.loads, then raw_decode. Returns parsed object or raises."""
    try:
        return json.loads(content, strict=False)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder(strict=False)
    obj, _ = decoder.raw_decode(content)
    return obj


def _fix_trailing_commas(content):
    return re.sub(r',\s*([}\]])', r'\1', content)


def _fix_unescaped_quotes(content):
    """Iteratively escape double quotes inside JSON string values that break parsing."""
    text = content
    for _ in range(200):
        try:
            json.loads(text, strict=False)
            return text
        except json.JSONDecodeError as e:
            if "delimiter" not in e.msg and "property name" not in e.msg:
                return text
            pos = e.pos
            found = -1
            for i in range(pos - 1, max(pos - 50, -1), -1):
                if text[i] == '"' and (i == 0 or text[i - 1] != '\\'):
                    found = i
                    break
            if found < 0:
                return text
            text = text[:found] + '\\"' + text[found + 1:]
    return text


def _fix_unquoted_values(content):
    """Fix unquoted string values like  "language": coding  ->  "language": "coding" """
    return re.sub(
        r':\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*([,}\]\n])',
        lambda m: ': "' + m.group(1) + '"' + m.group(2),
        content,
    )


def _fix_unquoted_keys(content):
    """Fix unquoted property names like  paths: [  ->  "paths": [ """
    return re.sub(
        r'(?<=[\{,\n])\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:',
        lambda m: ' "' + m.group(1) + '":',
        content,
    )


def _close_truncated(content):
    """Close unclosed strings, arrays, and objects in truncated JSON."""
    text = content.rstrip()

    text = re.sub(r'([,{])\s*"[^"]*"\s*:\s*[a-zA-Z_]\w*\s*$', r'\1', text)
    text = re.sub(r'([,{])\s*"[^"]*"\s*:\s*$', r'\1', text)
    text = re.sub(r'([,{])\s*"[^"]*"\s*$', r'\1', text)
    text = re.sub(r'([,{])\s*[a-zA-Z_]\w*(?:\s+\w+)*\s*$', r'\1', text)
    text = text.rstrip()

    stack = []
    in_string = False
    escape = False
    for ch in text:
        if escape:
            escape = False
            continue
        if ch == '\\' and in_string:
            escape = True
            continue
        if ch == '"' and not escape:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch in '[{':
            stack.append(ch)
        elif ch == ']' and stack and stack[-1] == '[':
            stack.pop()
        elif ch == '}' and stack and stack[-1] == '{':
            stack.pop()

    if in_string:
        text += '"'
    for opener in reversed(stack):
        text += ']' if opener == '[' else '}'
    return text


def _pre_escape_concat_quotes(content):
    """Pre-escape double quotes in Java string concatenation patterns."""
    return re.sub(
        r"""(?<=['\=\(\)\]])"\s*\+""",
        r"""\"\+""",
        re.sub(
            r"""\+\s*"(?=['\)\]\w])""",
            r"""+\"""",
            content,
        ),
    )


def _salvage_complete_elements(content):
    """Find the last complete top-level array element and discard the rest."""
    text = _pre_escape_concat_quotes(
        _fix_trailing_commas(_fix_unquoted_keys(_fix_unquoted_values(content)))
    )
    stack = []
    in_string = False
    escape = False
    last_good = -1

    for i, ch in enumerate(text):
        if escape:
            escape = False
            continue
        if ch == '\\' and in_string:
            escape = True
            continue
        if ch == '"' and not escape:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch in '[{':
            stack.append(ch)
        elif ch == ']' and stack and stack[-1] == '[':
            stack.pop()
            if len(stack) == 0:
                last_good = i + 1
        elif ch == '}' and stack and stack[-1] == '{':
            stack.pop()
            if len(stack) <= 1:
                last_good = i + 1

    if last_good <= 0:
        return None

    salvaged = text[:last_good]
    stack2 = []
    in_string2 = False
    escape2 = False
    for ch in salvaged:
        if escape2:
            escape2 = False
            continue
        if ch == '\\' and in_string2:
            escape2 = True
            continue
        if ch == '"' and not escape2:
            in_string2 = not in_string2
            continue
        if in_string2:
            continue
        if ch in '[{':
            stack2.append(ch)
        elif ch == ']' and stack2 and stack2[-1] == '[':
            stack2.pop()
        elif ch == '}' and stack2 and stack2[-1] == '{':
            stack2.pop()

    for opener in reversed(stack2):
        salvaged += ']' if opener == '[' else '}'
    return _fix_trailing_commas(salvaged)


def repair_and_parse_json(raw_content):
    """
    Attempt to parse LLM output as JSON with cumulative repair strategies.
    Returns (parsed_object, error_message). error_message is None on success.
    """
    raw_content = _normalize_llm_content(raw_content)
    if not raw_content.strip():
        return None, "Empty LLM response"

    content = _strip_fences_and_locate(raw_content)
    if content is None:
        return None, "No JSON structure found in response"

    # Phase 1: try raw content
    try:
        return _try_parse(content), None
    except json.JSONDecodeError:
        pass

    # Phase 2: apply fixes cumulatively
    text = content
    text = _fix_invalid_escapes(text)
    text = _fix_trailing_commas(text)
    try:
        return _try_parse(text), None
    except json.JSONDecodeError:
        pass

    text = _fix_unescaped_quotes(text)
    try:
        return _try_parse(text), None
    except json.JSONDecodeError:
        pass

    text = _fix_unquoted_keys(_fix_unquoted_values(text))
    try:
        return _try_parse(text), None
    except json.JSONDecodeError:
        pass

    # Phase 3: close truncated structures
    text = _close_truncated(text)
    text = _fix_trailing_commas(text)
    try:
        return _try_parse(text), None
    except json.JSONDecodeError:
        pass

    text = _fix_unescaped_quotes(text)
    try:
        return _try_parse(text), None
    except json.JSONDecodeError:
        pass

    # Phase 4: salvage last complete array elements
    salvaged = _salvage_complete_elements(content)
    if salvaged:
        salvaged = _fix_unescaped_quotes(salvaged)
        try:
            return _try_parse(salvaged), None
        except json.JSONDecodeError:
            pass

    return None, "All repair strategies exhausted"
