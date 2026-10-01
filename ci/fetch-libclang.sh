#!/usr/bin/env bash
#
# Fetch, verify and lay out the pinned libclang a release vendors beside
# `cindex` (po-av01j.49).
#
#   ci/fetch-libclang.sh <rust-target-triple> <outdir>
#
# Writes <outdir>/libclang/:
#
#   libclang.so | libclang.dylib   the pinned library for <triple>
#   include/                       clang's builtin headers, same version
#   LICENSE.TXT                    LLVM's license, which redistribution needs
#
# cindex finds that directory beside its own (symlink-resolved) executable,
# loads the library from it, and passes it to every TU as -resource-dir. See
# crates/cindex/src/engine.rs.
#
# Everything comes from crates/cindex/libclang.pin (LIBCLANG_PIN overrides the
# path, for tests). Each download is checked against the pinned sha256 BEFORE
# anything is unpacked, and the bundle is assembled in a scratch directory and
# moved into place only once complete: a mismatch, an unpinned triple or a
# failed extraction exits non-zero with <outdir>/libclang absent, so the
# release fails instead of packing a partial or unverified engine.
set -euo pipefail

die() { printf 'fetch-libclang: %s\n' "$*" >&2; exit 1; }

[ "$#" -eq 2 ] || die "usage: $0 <rust-target-triple> <outdir>"
triple=$1
outdir=$2

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
pin=${LIBCLANG_PIN:-$here/../crates/cindex/libclang.pin}
[ -f "$pin" ] || die "no pin file at $pin"

for tool in curl unzip tar; do
  command -v "$tool" >/dev/null 2>&1 || die "\`$tool\` is required"
done

# Rows of the pin with comments and blank lines stripped.
rows() { sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$pin"; }

lib_rows=$(rows | awk -v t="$triple" '$1 == "lib" && $2 == t')
[ -n "$lib_rows" ] || die "$triple has no \`lib\` line in $pin; pin an engine for it before releasing it"
[ "$(printf '%s\n' "$lib_rows" | wc -l)" -eq 1 ] || die "$triple is pinned more than once in $pin"
read -r _ _ lib_url lib_sha lib_member license_member <<<"$lib_rows"
[ -n "${license_member:-}" ] || die "malformed lib line for $triple in $pin"

hdr_rows=$(rows | awk '$1 == "headers"')
[ "$(printf '%s\n' "$hdr_rows" | grep -c .)" -eq 1 ] || die "$pin needs exactly one \`headers\` line"
read -r _ hdr_url hdr_sha hdr_dir <<<"$hdr_rows"
[ -n "${hdr_dir:-}" ] || die "malformed headers line in $pin"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

mkdir -p "$outdir"
scratch=$(mktemp -d "$outdir/.libclang.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

# Download to a file, then refuse it unless it matches the pin.
fetch() {
  local url=$1 want=$2 dest=$3 got
  curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
    --connect-timeout 30 --max-time 900 -o "$dest" "$url" ||
    die "download failed: $url"
  got=$(sha256 "$dest")
  [ "$got" = "$want" ] ||
    die "checksum mismatch for $url: pinned $want, got $got (refusing to ship it)"
}

fetch "$lib_url" "$lib_sha" "$scratch/lib.whl"
fetch "$hdr_url" "$hdr_sha" "$scratch/headers.tar.xz"

bundle=$scratch/libclang
mkdir -p "$bundle/include" "$scratch/src"

lib_name=$(basename "$lib_member")
unzip -p "$scratch/lib.whl" "$lib_member" >"$bundle/$lib_name" ||
  die "$lib_member is not in $lib_url"
[ -s "$bundle/$lib_name" ] || die "$lib_member in $lib_url is empty"
chmod 0644 "$bundle/$lib_name"
unzip -p "$scratch/lib.whl" "$license_member" >"$bundle/LICENSE.TXT" ||
  die "$license_member is not in $lib_url"

tar -xJf "$scratch/headers.tar.xz" -C "$scratch/src" "$hdr_dir" ||
  die "$hdr_dir is not in $hdr_url"
# Only the headers: lib/Headers also carries its CMake build file.
rm -f "$scratch/src/$hdr_dir/CMakeLists.txt"
cp -R "$scratch/src/$hdr_dir/." "$bundle/include/"
[ -f "$bundle/include/stddef.h" ] || die "$hdr_dir in $hdr_url has no stddef.h; wrong directory?"

rm -rf "$outdir/libclang"
mv "$bundle" "$outdir/libclang"
printf 'fetch-libclang: %s -> %s (%s)\n' "$triple" "$outdir/libclang" "$lib_name" >&2
