#!/usr/bin/env python3
"""Fail when rvl-cli starts to carry content instead of mechanism.

The boundary: rvl-cli is a public Apache-2.0 repository and holds mechanism
only. Every commercial artifact (judgment rulesets, the commercial spec tier,
decision-model weights, temperatures, thresholds, prompts, skills, agents,
labels, eval gold) is served by the Revelara API behind an API key. The OSS
vocabulary tier holds only enumerable ecosystem facts and is served too, not
built in. So content reaches the binary over the wire, verified, and never
from the source tree.

Two rules, each a failure (there is no warn-only mode):

  embed     a .rs file uses include_str!, include_bytes! or include_dir!
            and is not allowlisted for it.
  artifact  a file in the repository (testdata and goldens included) has the
            shape of a signed spec-cache artifact, a judgments ruleset or
            model weights: by extension (*.onnx, *.safetensors, *.sig, a
            tarball, ...) or, for JSON, by the envelope and manifest schemas
            the CLI parses (crates/rvl-cache).

A third failure keeps the allowlist honest: an entry that matches nothing is
stale and must be removed.

The allowlist (ci/content-boundary-allowlist.txt) holds one entry per line,
`<rule> <path> <reason>`; the reason is required.

Usage: check-content-boundary.py [--root DIR] [--allowlist FILE]
Files are those git knows of under DIR: tracked, plus untracked files that
are not ignored, so a local run catches a file before it is committed.
"""

import argparse
import json
import os
import re
import subprocess
import sys

BOUNDARY = (
    "rvl-cli is public and holds mechanism only; serve this content from the "
    "Revelara API behind a key instead (see ci/check-content-boundary.py)"
)

RULES = ("embed", "artifact")

EMBED_RE = re.compile(r"\binclude_(str|bytes|dir)!\s*[(\[{]")

WEIGHT_EXTS = (".onnx", ".ort", ".safetensors", ".gguf", ".ggml", ".pt", ".pth", ".ckpt")
SIGNATURE_EXTS = (".sig", ".minisig")
TARBALL_EXTS = (".tar", ".tgz", ".tbz2", ".txz", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst")

# JSON larger than this is not parsed for its shape. A real artifact is
# caught by extension or is small enough; this bounds the check's run time.
MAX_JSON_BYTES = 64 * 1024 * 1024


def list_files(root):
    out = subprocess.run(
        ["git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        check=True,
        capture_output=True,
    ).stdout
    # ls-files lists a tracked file deleted from the work tree too.
    names = sorted({n for n in out.decode().split("\0") if n})
    return [n for n in names if os.path.isfile(os.path.join(root, n))]


def strip_line_comment(line):
    """Drop a // comment so prose that names a macro is not an embed.

    Good enough for a guard: a `//` inside a string literal ends the line
    early, which can only hide text after it, never invent an embed.
    """
    i = line.find("//")
    return line if i < 0 else line[:i]


def embeds(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            m = EMBED_RE.search(strip_line_comment(line))
            if m:
                yield n, m.group(0).rstrip("([{ \t")


def is_judgments(value):
    return (
        isinstance(value, list)
        and len(value) > 0
        and all(isinstance(e, dict) and {"api", "scope", "verdict"} <= e.keys() for e in value)
    )


def json_shape(doc):
    """Name the artifact shape a parsed JSON document has, or None."""
    if is_judgments(doc):
        return "a judgments ruleset (entries with api, scope and verdict)"
    if not isinstance(doc, dict):
        return None
    keys = doc.keys()
    # crates/rvl-cache/src/lib.rs `Envelope`: specs.json, as signed.
    if {"schema", "content_version", "specs"} <= keys:
        return "a spec-cache envelope (schema, content_version, specs)"
    if is_judgments(doc.get("judgments")):
        return "a judgments ruleset (a judgments section)"
    # crates/rvl-cache/src/model.rs `ModelManifest`: the decision model.
    if {"schema_version", "model_id", "files"} <= keys:
        return "a decision-model manifest (schema_version, model_id, files)"
    # The signed response the model endpoint answers.
    if {"manifest", "signature"} <= keys:
        return "a signed manifest response (manifest, signature)"
    return None


def artifact_shape(root, name):
    lower = name.lower()
    if lower.endswith(WEIGHT_EXTS):
        return "model weights (by extension)"
    if lower.endswith(SIGNATURE_EXTS):
        return "a detached signature of a signed artifact (by extension)"
    if lower.endswith(TARBALL_EXTS):
        return "a tarball, the shape of a packed spec cache (by extension)"
    if lower.endswith(".json"):
        path = os.path.join(root, name)
        if os.path.getsize(path) > MAX_JSON_BYTES:
            return None
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (ValueError, UnicodeDecodeError):
            return None
        return json_shape(doc)
    return None


def read_allowlist(path):
    """Return ({(rule, path): reason}, [errors])."""
    entries, errors = {}, []
    if not os.path.exists(path):
        return entries, errors
    with open(path, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 2)
            where = f"{path}:{n}"
            if len(parts) < 3:
                errors.append(f"{where}: allowlist entry needs `<rule> <path> <reason>`")
                continue
            rule, name, reason = parts
            if rule not in RULES:
                errors.append(f"{where}: unknown rule {rule!r} (one of {', '.join(RULES)})")
                continue
            entries[(rule, name)] = reason
    return entries, errors


def check(root, allowlist_path):
    allowed, errors = read_allowlist(allowlist_path)
    used = set()
    allowlist_name = os.path.relpath(os.path.abspath(allowlist_path), os.path.abspath(root))

    for name in list_files(root):
        if name == allowlist_name:
            continue
        if name.endswith(".rs"):
            hits = list(embeds(os.path.join(root, name)))
            if hits:
                if ("embed", name) in allowed:
                    used.add(("embed", name))
                else:
                    for n, macro in hits:
                        errors.append(
                            f"{name}:{n}: rule embed: {macro}! embeds content in the binary "
                            f"and this file is not allowlisted; {BOUNDARY}"
                        )
        shape = artifact_shape(root, name)
        if shape:
            if ("artifact", name) in allowed:
                used.add(("artifact", name))
            else:
                errors.append(f"{name}: rule artifact: has the shape of {shape}; {BOUNDARY}")

    for rule, name in sorted(set(allowed) - used):
        errors.append(
            f"{allowlist_name}: stale entry `{rule} {name}`: it matches nothing; remove it"
        )
    return errors


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--allowlist", default=None)
    args = ap.parse_args(argv)
    allowlist = args.allowlist or os.path.join(args.root, "ci", "content-boundary-allowlist.txt")
    errors = check(args.root, allowlist)
    for e in errors:
        print(e, file=sys.stderr)
    if errors:
        print(f"content boundary: {len(errors)} violation(s)", file=sys.stderr)
        return 1
    print("content boundary: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
