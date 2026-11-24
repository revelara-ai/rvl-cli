"""Tests for ci/check-content-boundary.py.

    python3 -I -B -m unittest discover -s ci -p 'test_*.py'

Each fixture tree is written to a temporary git repository at run time: a
committed fixture with a violation would make the check fail on this
repository itself.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "check-content-boundary.py")

spec = importlib.util.spec_from_file_location("check_content_boundary", SCRIPT)
ccb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ccb)

CLEAN = {
    "src/lib.rs": "// include_str!(\"x\") in a comment is prose\npub fn f() {}\n",
    "src/allowed.rs": 'const T: &str = include_str!("t.md");\n',
    "src/t.md": "template\n",
    "testdata/specs.json": json.dumps({"apis": [], "configs": []}),
    "testdata/plain.gz": "not a tarball",
    "ci/content-boundary-allowlist.txt": "embed src/allowed.rs the template the binary writes\n",
}

# One violation per rule, each in a file of its own.
VIOLATIONS = {
    "src/new_embed.rs": 'const B: &[u8] = include_bytes!(\n    "blob.bin"\n);\n',
    "src/dir_embed.rs": 'static D: Dir = include_dir!("$CARGO_MANIFEST_DIR/data");\n',
    "testdata/model.safetensors": "weights",
    "testdata/model.onnx": "weights",
    "testdata/specs.json.sig": "c2ln",
    "goldens/cache.tar.gz": "tarball",
    "testdata/cache/specs.json": json.dumps(
        {"schema": 1, "content_version": "2026-01-01.1", "specs": {}}
    ),
    "testdata/model/manifest.json": json.dumps(
        {"schema_version": 1, "model_id": "m", "files": [], "temperature": 1.0}
    ),
    "testdata/judgments.json": json.dumps(
        [{"api": "a.b", "scope": "runtime", "verdict": "surface", "severity": "high"}]
    ),
    "testdata/signed.json": json.dumps({"manifest": {}, "signature": "c2ln"}),
}


TREES = []


def tearDownModule():
    for d in TREES:
        shutil.rmtree(d, ignore_errors=True)


def make_tree(files):
    d = tempfile.mkdtemp()
    TREES.append(d)
    for name, body in files.items():
        path = os.path.join(d, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
    subprocess.run(["git", "init", "-q", d], check=True)
    subprocess.run(["git", "-C", d, "add", "-A"], check=True)
    return d


def run(files):
    d = make_tree(files)
    return ccb.check(d, os.path.join(d, "ci", "content-boundary-allowlist.txt"))


class ContentBoundaryTest(unittest.TestCase):
    def test_clean_tree_passes(self):
        self.assertEqual(run(CLEAN), [])

    def test_each_violation_fails_naming_file_and_rule(self):
        errors = run({**CLEAN, **VIOLATIONS})
        self.assertEqual(len(errors), len(VIOLATIONS), "\n".join(errors))
        for name in VIOLATIONS:
            hits = [e for e in errors if e.startswith(name + ":")]
            self.assertEqual(len(hits), 1, f"{name}: {errors}")
            rule = "embed" if name.endswith(".rs") else "artifact"
            self.assertIn(f"rule {rule}:", hits[0])
            self.assertIn("Revelara API", hits[0])

    def test_untracked_file_is_checked(self):
        d = make_tree(CLEAN)
        with open(os.path.join(d, "w.onnx"), "w") as f:
            f.write("weights")
        errors = ccb.check(d, os.path.join(d, "ci", "content-boundary-allowlist.txt"))
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("w.onnx: rule artifact:"))

    def test_allowlisted_artifact_passes(self):
        files = {
            **CLEAN,
            "testdata/model.onnx": "weights",
            "ci/content-boundary-allowlist.txt": CLEAN["ci/content-boundary-allowlist.txt"]
            + "artifact testdata/model.onnx toy fixture\n",
        }
        self.assertEqual(run(files), [])

    def test_stale_entry_fails(self):
        files = {
            **CLEAN,
            "ci/content-boundary-allowlist.txt": CLEAN["ci/content-boundary-allowlist.txt"]
            + "embed src/lib.rs no embed here\n",
        }
        errors = run(files)
        self.assertEqual(len(errors), 1)
        self.assertIn("stale entry `embed src/lib.rs`", errors[0])

    def test_entry_without_reason_fails(self):
        files = {**CLEAN, "ci/content-boundary-allowlist.txt": "embed src/allowed.rs\n"}
        errors = run(files)
        self.assertTrue(any("needs `<rule> <path> <reason>`" in e for e in errors), errors)
        self.assertTrue(any(e.startswith("src/allowed.rs:1: rule embed:") for e in errors), errors)

    def test_main_exits_nonzero_on_violation(self):
        d = make_tree({**CLEAN, "x.gguf": "weights"})
        r = subprocess.run(
            ["python3", "-I", SCRIPT, "--root", d], capture_output=True, text=True
        )
        self.assertEqual(r.returncode, 1)
        self.assertIn("x.gguf: rule artifact:", r.stderr)
        r = subprocess.run(
            ["python3", "-I", SCRIPT, "--root", make_tree(CLEAN)], capture_output=True, text=True
        )
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
