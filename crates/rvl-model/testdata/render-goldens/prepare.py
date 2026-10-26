"""Turn label-export rows into model inputs.

The export is the backend's `worker -export-labels` (docs/scan-flywheel/label-export.md).
An input holds what rvl has at a site: the class, the published expectation,
the scope, the code. It never holds what a machine decided about the site
(engine verdict, votes, reasons, research, the adjudicator's facts), and it
never holds the judge instructions, which are written for a chat model and
change with the panel prompt.
"""
from __future__ import annotations

import json
import re

LABELS = ("violates", "satisfies", "not_applicable", "abstain")
_LABEL_OF = {"violates": 0, "satisfies": 1, "not_applicable": 2, "abstain": 3, "unsure": 3}
_EXPECTATION = re.compile(r"Published expectation for this class: (.*?)(?:\n\n|\Z)", re.S)
_FRAME_QUESTION = re.compile(r"^Question \((RC-\d+), (v\d+)\): (.+)$", re.M)
_FRAME_CELLS = re.compile(r"^Cells of the RC-\d+ frame:\n((?:  \S.*\n?)+)", re.M)
_CELL_LINE = re.compile(r"^\s*([MSC]\d+[a-z]*)\s")
_CONTROL_NAME = re.compile(r"^Control meaning: RC-\d+ - (.+)$", re.M)
SNIPPET_MAX_CHARS = 6000
EVIDENCE_MAX_CHARS = 6000
CONSTRUCTION_MAX_CHARS = 1500
CALLER_MAX_CHARS = 1500
CALLERS_MAX = 2


def read_rows(path: str):
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def label_of(row: dict) -> int | None:
    return _LABEL_OF.get(row.get("verdict"))


def family_of(cls: str) -> str:
    """The package of a class: what the report groups by. `net/http.Client.Do`
    is `net/http`; a Go import path keeps its dots before the last slash."""
    head, slash, tail = cls.rpartition("/")
    first = tail.split(".", 1)[0]
    return head + slash + first


_LANGUAGE_BY_SUFFIX = {".go": "go", ".py": "python", ".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript",
                       ".mjs": "javascript", ".java": "java", ".kt": "kotlin", ".rs": "rust", ".rb": "ruby", ".cs": "csharp", ".php": "php"}


def language_of(row: dict) -> str:
    """The recorded language, else the one the file name gives. The export has
    no language for most comparator repositories."""
    recorded = (row.get("language") or "").strip().lower()
    if recorded:
        return recorded
    name = row.get("file") or ""
    dot = name.rfind(".")
    return _LANGUAGE_BY_SUFFIX.get(name[dot:].lower(), "unknown") if dot >= 0 else "unknown"


def expectation_of(row: dict) -> str:
    m = _EXPECTATION.search((row.get("question") or {}).get("text") or "")
    return " ".join(m.group(1).split()) if m else ""


def question_of(row: dict) -> str:
    """Which question a row answers: the control of its frame, or "bound"
    for the bound question (is this blocking call bounded)."""
    if row.get("kind") == "frame_question":
        return row.get("control") or "bound"
    return "bound"


def frame_lines(row: dict) -> list[str]:
    """The frame's control, question and cells, as the judges read them.
    Empty for a row of the bound question."""
    if row.get("kind") != "frame_question":
        return []
    text = (row.get("question") or {}).get("text") or ""
    q = _FRAME_QUESTION.search(text)
    cells = _FRAME_CELLS.search(text)
    name = _CONTROL_NAME.search(text)
    out = [f"Control: {row.get('control', '')} {name.group(1).strip() if name else ''}".rstrip(),
           f"Question: {q.group(3).strip() if q else ''}"]
    if cells:
        out += ["Cells:"] + [" ".join(line.split()) for line in cells.group(1).splitlines() if line.strip()]
    return out


def frame_cells(row: dict, frame_files: dict | None = None) -> list[str]:
    """The cell ids of the row's frame version. Empty for a bound-question row,
    and for a frame row whose version neither its text nor a frame file gives.
    frame_files is cells.read_frames of conformance/frames."""
    if row.get("kind") != "frame_question":
        return []
    text = (row.get("question") or {}).get("text") or ""
    block = _FRAME_CELLS.search(text)
    if block:
        return [m.group(1) for m in map(_CELL_LINE.match, block.group(1).splitlines()) if m]
    q = _FRAME_QUESTION.search(text)
    version, ids = (frame_files or {}).get(row.get("control", ""), ("", []))
    return list(ids) if q and q.group(2) == version else []


def _citations_text(packet: dict) -> str:
    ev = packet.get("evidence")
    if not isinstance(ev, dict):
        return ""
    parts = []
    for c in ev.get("citations") or []:
        if isinstance(c, dict) and c.get("text"):
            parts.append(f"{c.get('path', '')}:{c.get('start_line', '')}-{c.get('end_line', '')}\n{c['text']}")
    return "\n\n".join(parts)[:EVIDENCE_MAX_CHARS]


def read_site_packets(path: str) -> dict:
    """The rvl retriever's packet of each label row, by label id. One line is
    {"id", "class", "exact", "packet"}; build_packets.py writes the file."""
    return {r["id"]: r["packet"] for r in read_rows(path)}


def _site_packet_lines(sp: dict) -> list[str]:
    """What the rvl retriever knows about a site and the export packet does
    not: the constant arguments, how the client was built, who calls the
    enclosing function. Short facts come first, a tokenizer cuts the tail."""
    out = []
    args = [f"{a.get('name') or a.get('index', '')}={a.get('value', '')}" for a in sp.get("const_args") or [] if isinstance(a, dict)]
    if args:
        out += ["", "Constant arguments: " + ", ".join(args)[:400]]
    built = [c for c in sp.get("client_construction") or [] if isinstance(c, dict) and c.get("source")]
    if built:
        scope = sp.get("client_construction_scope") or "unknown"
        out += ["", f"How {sp.get('client_type') or 'the client'} is built (found by {scope}):"]
        out += [f"{c.get('file', '')}:{c.get('line', '')}\n{c['source'][:CONSTRUCTION_MAX_CHARS]}" for c in built[:3]]
    elif sp.get("client_type"):
        out += ["", f"How {sp['client_type']} is built: not found in the repository"]
    return out


def _caller_lines(sp: dict) -> list[str]:
    callers = [c for c in sp.get("callers") or [] if isinstance(c, dict) and c.get("source")]
    out = []
    for c in callers[:CALLERS_MAX]:
        out += ["", f"Caller {c.get('symbol', '')} at {c.get('file', '')}:{c.get('line', '')}:", c["source"][:CALLER_MAX_CHARS]]
    return out


LAYOUTS = ("full", "compact")


def render_input(row: dict, evidence: str = "none", site_packet: dict | None = None, layout: str = "full") -> str:
    """evidence="citations" adds the code ranges the evidence adjudicator
    cited (the code only: not its summary of them, its facts or its votes).
    site_packet is the rvl retriever's packet of the site: the same context
    rvl has at scan time. A row without one renders as before.

    layout="compact" is for a short context (po-657l6.33, the CPU budget): the
    frame's question without its cells, and the site code before everything
    else, so a tokenizer that cuts the tail cuts the least useful text."""
    assert layout in LAYOUTS, layout
    packet = dict(row.get("packet") or {})
    sp = site_packet or {}
    if sp.get("enclosing_function_body") and not packet.get("enclosing_function"):
        packet["enclosing_function"], packet["enclosing_name"] = sp["enclosing_function_body"], sp.get("symbol") or ""
    frame = frame_lines(row)
    if layout == "compact":
        return "\n".join(_compact_lines(row, frame, packet, sp))
    out = [f"Class: {row.get('class', '')}"] + (frame or [f"Expectation: {expectation_of(row)}"]) + [
           f"Scope: {row.get('scope') or 'unknown'}",
           f"Language: {language_of(row)}",
           "",
           f"Site {row.get('site', '')}:",
           (packet.get("snippet") or "")[:SNIPPET_MAX_CHARS]]
    out += _site_packet_lines(sp)
    out += ["", "Imports:", packet.get("imports") or "(none found)"]
    if packet.get("callee_definition"):
        out += ["", f"Definition of {packet.get('callee_name', '')}, called at the site:", packet["callee_definition"][:SNIPPET_MAX_CHARS]]
    if packet.get("enclosing_function"):
        out += ["", f"Enclosing function {packet.get('enclosing_name', '')}:", packet["enclosing_function"][:SNIPPET_MAX_CHARS]]
    out += _caller_lines(sp)
    if evidence == "citations":
        text = _citations_text(packet)
        if text:
            out += ["", "Repository code:", text]
    return "\n".join(out)


def _compact_lines(row: dict, frame: list[str], packet: dict, sp: dict) -> list[str]:
    head = frame[:2] if frame else [f"Expectation: {expectation_of(row)}"]
    out = [f"Class: {row.get('class', '')}"] + head + [f"Scope: {row.get('scope') or 'unknown'}",
           f"Site {row.get('site', '')}:", (packet.get("snippet") or "")[:SNIPPET_MAX_CHARS]]
    out += _site_packet_lines(sp)
    if packet.get("enclosing_function"):
        out += ["", f"Enclosing function {packet.get('enclosing_name', '')}:", packet["enclosing_function"][:SNIPPET_MAX_CHARS]]
    if packet.get("callee_definition"):
        out += ["", f"Definition of {packet.get('callee_name', '')}, called at the site:", packet["callee_definition"][:SNIPPET_MAX_CHARS]]
    out += _caller_lines(sp)
    out += ["", "Imports:", packet.get("imports") or "(none found)"]
    return out


def examples(rows, evidence: str = "none", site_packets: dict | None = None, frames: bool = False, layout: str = "full",
             frame_files: dict | None = None):
    """frames=True keeps frame-question rows: one model for the bound
    question and every frame, each row carrying its own question and the
    cells of its frame version (frame_cells)."""
    site_packets = site_packets or {}
    for row in rows:
        label = label_of(row)
        if label is None or not ((row.get("packet") or {}).get("snippet") or "").strip():
            continue
        # A frame-question row asks whether the call retries or sits behind a
        # breaker, not whether it is bounded: another task, with another input.
        if row.get("kind") == "frame_question" and not frames:
            continue
        yield {"id": row["id"], "repo": row.get("repo", ""), "text": render_input(row, evidence, site_packets.get(row["id"]), layout), "label": label,
               "has_site_packet": row["id"] in site_packets,
               "question": question_of(row), "frame_cell": (row.get("frame_cell") or "").strip(),
               "frame_cells": frame_cells(row, frame_files),
               "language": language_of(row), "family": family_of(row.get("class", "")),
               "class": row.get("class", ""), "kind": row.get("kind", ""), "adjudicator_kind": row.get("adjudicator_kind", ""),
               "repo_split": row.get("repo_split", "")}
