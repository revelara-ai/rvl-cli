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

for tool in curl unzip; do
  command -v "$tool" >/dev/null 2>&1 || die "\`$tool\` is required"
done

# Rows of the pin with comments and blank lines stripped.
rows() { sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$pin"; }

lib_rows=$(rows | awk -v t="$triple" '$1 == "lib" && $2 == t')
[ -n "$lib_rows" ] || die "$triple has no \`lib\` line in $pin; pin a runtime for it before releasing it"
[ "$(printf '%s\n' "$lib_rows" | wc -l)" -eq 1 ] || die "$triple is pinned more than once in $pin"
read -r _ _ url want lib_member license_member <<<"$lib_rows"
[ -n "${license_member:-}" ] || die "malformed lib line for $triple in $pin"
# The notices ship beside the license. A license at the archive root gives
# `ThirdPartyNotices.txt`, not `./ThirdPartyNotices.txt`, which unzip would
# not match.
license_dir=$(dirname "$license_member")
if [ "$license_dir" = . ]; then
  notices_member=ThirdPartyNotices.txt
else
  notices_member=$license_dir/ThirdPartyNotices.txt
fi

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
  --connect-timeout 30 --max-time 900 -o "$scratch/runtime.nupkg" "$url" ||
  die "download failed: $url"
got=$(sha256 "$scratch/runtime.nupkg")
[ "$got" = "$want" ] ||
  die "checksum mismatch for $url: pinned $want, got $got (refusing to ship it)"

# The package is a zip (a NuGet .nupkg) and every member is a regular file.
mkdir -p "$scratch/src"
unzip -q "$scratch/runtime.nupkg" "$lib_member" "$license_member" "$notices_member" -d "$scratch/src" ||
  die "$lib_member, $license_member or $notices_member is not in $url"

bundle=$scratch/onnxruntime
mkdir -p "$bundle"
lib_name=$(basename "$lib_member")
[ -f "$scratch/src/$lib_member" ] || die "$lib_member is not in $url"
cp "$scratch/src/$lib_member" "$bundle/$lib_name"
[ -s "$bundle/$lib_name" ] || die "$lib_member in $url is empty"
chmod 0644 "$bundle/$lib_name"
cp "$scratch/src/$license_member" "$bundle/LICENSE"
cp "$scratch/src/$notices_member" "$bundle/ThirdPartyNotices.txt"

rm -rf "$outdir/onnxruntime"
mv "$bundle" "$outdir/onnxruntime"
printf 'fetch-onnxruntime: %s -> %s (%s)\n' "$triple" "$outdir/onnxruntime" "$lib_name" >&2
