#!/usr/bin/env bash
#
# Fetch, verify and lay out the pinned ONNX Runtime a release vendors beside
# `rvl`.
#
#   ci/fetch-onnxruntime.sh <rust-target-triple> <outdir>
#
# Writes <outdir>/onnxruntime/:
#
#   libonnxruntime.so | libonnxruntime.dylib   the pinned library for <triple>
#   LICENSE                                    ONNX Runtime's license
#   ThirdPartyNotices.txt                      the notices it ships with
#
# rvl-model finds that directory beside the (symlink-resolved) executable and
# loads the library from it. See crates/rvl-model/src/runtime.rs.
#
# Everything comes from crates/rvl-model/onnxruntime.pin (ONNXRUNTIME_PIN
# overrides the path, for tests). The download is checked against the pinned
# sha256 BEFORE anything is unpacked, and the bundle is assembled in a scratch
# directory and moved into place only once complete: a mismatch, an unpinned
# triple or a failed extraction exits non-zero with <outdir>/onnxruntime
# absent, so the build fails instead of packing a partial or unverified
# runtime.
set -euo pipefail

die() { printf 'fetch-onnxruntime: %s\n' "$*" >&2; exit 1; }

[ "$#" -eq 2 ] || die "usage: $0 <rust-target-triple> <outdir>"
triple=$1
outdir=$2

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
pin=${ONNXRUNTIME_PIN:-$here/../crates/rvl-model/onnxruntime.pin}
[ -f "$pin" ] || die "no pin file at $pin"

for tool in curl tar; do
  command -v "$tool" >/dev/null 2>&1 || die "\`$tool\` is required"
done

# Rows of the pin with comments and blank lines stripped.
rows() { sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$pin"; }

lib_rows=$(rows | awk -v t="$triple" '$1 == "lib" && $2 == t')
[ -n "$lib_rows" ] || die "$triple has no \`lib\` line in $pin; pin a runtime for it before releasing it"
[ "$(printf '%s\n' "$lib_rows" | wc -l)" -eq 1 ] || die "$triple is pinned more than once in $pin"
read -r _ _ url want lib_member license_member <<<"$lib_rows"
[ -n "${license_member:-}" ] || die "malformed lib line for $triple in $pin"
notices_member=$(dirname "$license_member")/ThirdPartyNotices.txt

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

mkdir -p "$outdir"
scratch=$(mktemp -d "$outdir/.onnxruntime.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
  --connect-timeout 30 --max-time 900 -o "$scratch/runtime.tgz" "$url" ||
  die "download failed: $url"
got=$(sha256 "$scratch/runtime.tgz")
[ "$got" = "$want" ] ||
  die "checksum mismatch for $url: pinned $want, got $got (refusing to ship it)"

# The library member is a symlink to the versioned file beside it, so the
# whole lib/ directory is unpacked and the link is followed on copy.
mkdir -p "$scratch/src"
lib_dir=$(dirname "$lib_member")
tar -xzf "$scratch/runtime.tgz" -C "$scratch/src" "$lib_dir" "$license_member" "$notices_member" ||
  die "$lib_dir, $license_member or $notices_member is not in $url"

bundle=$scratch/onnxruntime
mkdir -p "$bundle"
lib_name=$(basename "$lib_member")
[ -e "$scratch/src/$lib_member" ] || die "$lib_member is not in $url (or is a dangling link)"
cp -L "$scratch/src/$lib_member" "$bundle/$lib_name"
[ -s "$bundle/$lib_name" ] || die "$lib_member in $url is empty"
chmod 0644 "$bundle/$lib_name"
cp "$scratch/src/$license_member" "$bundle/LICENSE"
cp "$scratch/src/$notices_member" "$bundle/ThirdPartyNotices.txt"

rm -rf "$outdir/onnxruntime"
mv "$bundle" "$outdir/onnxruntime"
printf 'fetch-onnxruntime: %s -> %s (%s)\n' "$triple" "$outdir/onnxruntime" "$lib_name" >&2
