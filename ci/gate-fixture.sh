#!/usr/bin/env bash
#
# Build the repository the reference CI job (docs/examples/rvl-gate.yml) is
# run against by .github/workflows/rvl-gate-reference.yml.
#
#   ci/gate-fixture.sh <dir>
#
# <dir> becomes a git repository holding a copy of ci/smoke/repo (one
# unbounded call each in Go, C and Python, so the full scan reads every lane
# the archive carries a helper for) committed on `main`, and a branch
# `change`, checked out, that adds one Python file whose only call is bounded.
# That is the shape of a pull request's checkout: `main` is the base the
# gate's --changed-only diverges from, and the change it judges has a code
# site to read and nothing to block.
#
# A pull_request run exports GITHUB_BASE_REF=main, which names this `main`.
# A scheduled or post-release run exports no base ref, so .revelara.yaml
# names it, at the bottom of the base-ref chain.
set -euo pipefail

die() { printf 'gate-fixture: %s\n' "$*" >&2; exit 1; }

[ "$#" -eq 1 ] || die "usage: $0 <dir>"
dir=$1
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[ ! -e "$dir" ] || die "$dir already exists"

cp -R "$here/smoke/repo" "$dir"
cd "$dir"
cat >.revelara.yaml <<'EOF'
scanner:
  base_ref: main
EOF

git() {
  command git -c user.name=rvl-gate-fixture -c user.email=fixture@example.com \
    -c init.defaultBranch=main -c commit.gpgsign=false "$@"
}
git init -q
git add -A
git commit -qm "base"
git checkout -qb change
cat >client.py <<'EOF'
import requests


def fetch(url):
    return requests.get(url, timeout=5)
EOF
git add client.py
git commit -qm "change"
