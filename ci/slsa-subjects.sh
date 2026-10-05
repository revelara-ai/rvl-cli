#!/usr/bin/env bash
#
# Print the SLSA provenance subjects for this release: one `sha256sum` line per
# file the release uploads.
#
#   ci/slsa-subjects.sh <dir>
#
# <dir> is the merged `artifacts-*` download of the release run (see
# slsa-provenance.yml). The file set is the one the `host` job in release.yml
# uploads: every file in <dir> except the granular `*-dist-manifest.json`
# files, which `host` deletes before `gh release create`. Keep the two in step:
# a file that is uploaded and not listed here is a release asset with no
# provenance.
#
# The hashes are of the build run's own artifacts, not of a re-download of the
# release, so an asset that was swapped on the release after upload does not
# get attested; it fails verification instead.
set -euo pipefail

die() { printf 'slsa-subjects: %s\n' "$*" >&2; exit 1; }

[ "$#" -eq 1 ] || die "usage: $0 <dir-with-release-artifacts>"
dir=$1
[ -d "$dir" ] || die "not a directory: $dir"

cd "$dir"
files=()
while IFS= read -r -d '' f; do
  files+=("${f#./}")
done < <(find . -maxdepth 1 -type f ! -name '*-dist-manifest.json' -print0 | LC_ALL=C sort -z)

# An empty list would make the generator sign provenance for nothing, and the
# release would look attested.
[ "${#files[@]}" -gt 0 ] || die "no release artifacts in $dir"

sha256sum -- "${files[@]}"
