#!/usr/bin/env bash
#
# Smoke-test one release archive the way a user meets it.
#
#   ci/smoke-archive.sh <rvl-TRIPLE.tar.xz> <version>
#
# Unpacks the archive into a scratch directory, checks that `rvl --version`
# names <version>, and scans a copy of ci/smoke/repo with the seed specs in
# ci/smoke/specs.json. The fixture has one unbounded call per lane the archive
# carries a helper for (Go: goindex, C: cindex and its vendored libclang,
# Python: the embedded pyindex), and the scan must:
#
#   * exit 0 or 3 under --strict (1 is a broken scanner or a failed lane);
#   * report every one of those lanes `scanned` with at least one site;
#   * resolve goindex and cindex from the archive itself (`bundled`) and
#     pyindex from the copy embedded in rvl (`embedded`), so nothing on the
#     runner stands in for a helper the archive should carry;
#   * decide a `violates` site in each fixture source.
#
# The scan runs with HOME and the cache in the scratch directory and with every
# helper override unset. The fixture is copied out of the checkout first, so
# the scan sees no enclosing git repository. The runner needs the engines the
# archive does not carry, `go` for goindex and `python3` for pyindex; without
# one, that lane is not `scanned` and the smoke fails naming it.
set -euo pipefail

die() { printf 'smoke-archive: %s\n' "$*" >&2; exit 1; }

[ "$#" -eq 2 ] || die "usage: $0 <rvl-TRIPLE.tar.xz> <version>"
archive=$1
version=$2

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fixture=$here/smoke/repo
specs=$here/smoke/specs.json
[ -f "$archive" ] || die "no archive at $archive"
[ -d "$fixture" ] || die "no fixture repository at $fixture"
[ -f "$specs" ] || die "no seed specs at $specs"

for tool in tar jq; do
  command -v "$tool" >/dev/null 2>&1 || die "\`$tool\` is required"
done

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rvl-smoke.XXXXXX")
trap 'rm -rf "$work"' EXIT

# --- unpack ------------------------------------------------------------------
# A dist archive unpacks into one directory named after it.
mkdir "$work/unpacked"
tar -xJf "$archive" -C "$work/unpacked"
top=$(basename "$archive" .tar.xz)
bindir=$work/unpacked/$top
rvl=$bindir/rvl
[ -x "$rvl" ] || die "$(basename "$archive") has no executable $top/rvl"

# --- version -----------------------------------------------------------------
got=$("$rvl" --version)
[ "$got" = "rvl $version" ] || die "\`rvl --version\` printed '$got', expected 'rvl $version'"
echo "ok: $got"

# --- scan --------------------------------------------------------------------
cp -R "$fixture" "$work/repo"
mkdir "$work/home"
out=$work/findings.json
set +e
env -u RVL_GOINDEX -u RVL_PYINDEX -u RVL_RUSTINDEX -u RVL_TSINDEX \
  -u RVL_CSINDEX -u RVL_JAVAINDEX -u RVL_CINDEX -u RVL_HELPER_DIR \
  -u RVL_ALLOW_MISSING_HELPERS -u LIBCLANG_PATH \
  HOME="$work/home" RVL_CACHE_DIR="$work/cache" \
  "$rvl" scan "$work/repo" --strict --specs-file "$specs" --out "$out" \
  </dev/null >"$work/stdout" 2>"$work/stderr"
code=$?
set -e

fail() {
  printf 'smoke-archive: %s\n' "$*" >&2
  echo "--- rvl scan stdout" >&2
  cat "$work/stdout" >&2
  echo "--- rvl scan stderr" >&2
  cat "$work/stderr" >&2
  if [ -f "$out" ]; then
    echo "--- coverage" >&2
    jq '.coverage' "$out" >&2 || true
  fi
  exit 1
}

case "$code" in
  0 | 3) ;;
  *) fail "rvl scan exited $code; 0 (clean) or 3 (blocked) means it reached a verdict" ;;
esac
[ -f "$out" ] || fail "rvl scan wrote no --out document"

# Each lane: its name in coverage (lowercased), where its helper must come
# from, and the fixture source it must decide.
lanes='[
  {"lang": "go",     "source": "bundled",  "file": "main.go"},
  {"lang": "c/c++",  "source": "bundled",  "file": "src/fetch.c"},
  {"lang": "python", "source": "embedded", "file": "svc.py"}
]'

# shellcheck disable=SC2016  # $lanes/$top/$l are jq variables, not shell ones.
problems=$(jq -r --argjson lanes "$lanes" --arg top "/$top/" '
  . as $doc
  | .coverage as $c
  | ( $c.lang_status | map(select(.state != "skipped")) ) as $status
  | ( $status | map(.lang | ascii_downcase) | sort ) as $seen
  | ( $lanes | map(.lang) | sort ) as $want
  | [
      ( if $seen != $want then "detected lanes \($seen), expected \($want)" else empty end ),
      ( $lanes[] as $l
        | ( [ $status[] | select((.lang | ascii_downcase) == $l.lang) ] | first ) as $s
        | ( [ $c.retrievers[] | select((.lang | ascii_downcase) == $l.lang) ] | first ) as $r
        | ( if $s == null then empty
            elif $s.state != "scanned" or ((($s.detail | tonumber?) // 0) < 1)
            then "\($l.lang): \($s.state) (\($s.detail)), expected scanned with at least one site"
            else empty end ),
          ( if $r == null then "\($l.lang): no retriever row"
            elif $r.source != $l.source
            then "\($l.lang): helper came from \($r.source) (\($r.path)), expected \($l.source)"
            elif $l.source == "bundled" and ($r.path | contains($top) | not)
            then "\($l.lang): helper \($r.path) is not the one in the archive"
            else empty end ),
          ( if [ $doc.sites[] | select(.verdict == "violates" and (.site_id | contains($l.file))) ]
               | length == 0
            then "\($l.lang): no violates site in \($l.file)"
            else empty end )
      ),
      ( if ($c.degraded | length) > 0 then "degraded lanes: \($c.degraded)" else empty end )
    ]
  | .[]' "$out") || fail "could not read $out"
[ -z "$problems" ] || fail "$problems"

echo "ok: scan exited $code; Go, C/C++ and Python each scanned and decided a violation"
