#!/usr/bin/env bash
#
# Render Casks/rvl.rb for revelara-ai/homebrew-tap out of this release's own
# cargo-dist output.
#
#   ci/render-cask.sh <dir> > Casks/rvl.rb
#
# <dir> is a flat directory holding everything the release produced: the
# per-target `*-dist-manifest.json` files AND the built `.tar.xz` archives.
# In CI that is the merged `artifacts-*` download (see publish-cask.yml); it
# also works against a directory you assembled by hand for a dry run.
#
# WHY THIS EXISTS
# ---------------
# The tap has only Casks/, no Formula/. cargo-dist 0.32 emits a Homebrew
# FORMULA and has no cask support, and a Formula/rvl.rb landing beside
# Casks/rvl.rb would both make `brew install revelara-ai/tap/rvl` ambiguous and
# strand every existing cask user, because `brew upgrade` does not migrate
# across the two namespaces. So cargo-dist's homebrew installer is off (see
# dist-workspace.toml) and the cask is rendered here.
#
# NOTHING IS HARDCODED THAT THE RELEASE ALREADY KNOWS: version, archive
# filenames and sha256 checksums all come from dist-manifest.json, and the
# staged directory name and the set of installable binaries are read back off
# the real archives. If any of that stops lining up, this script fails the
# release instead of publishing a cask that 404s or silently drops a helper.
set -euo pipefail

die() { printf 'render-cask: %s\n' "$*" >&2; exit 1; }

[ "$#" -eq 1 ] || die "usage: $0 <dir-with-dist-manifests-and-archives>"
dir=$1
[ -d "$dir" ] || die "not a directory: $dir"

# The cargo-dist app whose archives back the cask. The workspace also builds
# `rvl-eval`, which must never end up in the tap.
APP=rvl
CASK_TOKEN=rvl

# ---------------------------------------------------------------------------
# ORDERING CONSTRAINT — READ BEFORE TAGGING A RELEASE
# ---------------------------------------------------------------------------
# The cask points at github.com/revelara-ai/rvl-cli, which is the name THIS
# repo only takes once the rename lands (po-av01j.154: the Go rvl-cli repo is
# moved aside first, then this one is renamed into the freed name). Until that
# happens this repo is still `rvlscan`, its releases live under
# .../rvlscan/releases/download/..., and every url below would be a 404.
#
# So: this code may land before the rename, but the FIRST RELEASE TAG MUST COME
# AFTER IT. Tag v1.0.0 early and you publish a cask full of dead links to every
# brew user in one commit.
#
# It is deliberately not derived from the manifest's `hosting` block: that
# follows Cargo.toml's `repository` key, so a stale value there would quietly
# publish urls pointing at the wrong repo. Naming it here means the ordering
# hazard is stated where the url is built. Override for a dry run only.
RELEASE_REPO="${CASK_RELEASE_REPO:-revelara-ai/rvl-cli}"

# Cask metadata, held identical to what goreleaser used to emit so that a
# `brew upgrade` sees an ordinary version bump and not a rewritten cask. These
# are presentation strings, not release facts, which is why they are not read
# out of the manifest.
CASK_NAME="rvl"
CASK_DESC="Revelara CLI — scan your codebase for reliability risks"
CASK_HOMEPAGE="https://revelara.ai"

# Rust target triple -> the cask's (os block, arch block) pair.
triple_blocks() {
  case "$1" in
    x86_64-apple-darwin)       echo "on_macos on_intel" ;;
    aarch64-apple-darwin)      echo "on_macos on_arm" ;;
    x86_64-unknown-linux-gnu)  echo "on_linux on_intel" ;;
    aarch64-unknown-linux-gnu) echo "on_linux on_arm" ;;
    *) return 1 ;;
  esac
}
# Emission order, so the file's shape is stable across releases.
TRIPLES="x86_64-apple-darwin aarch64-apple-darwin x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu"

# ---------------------------------------------------------------------------
# Collect the manifests
# ---------------------------------------------------------------------------
manifests=()
while IFS= read -r m; do manifests+=("$m"); done < <(
  find "$dir" -maxdepth 2 -type f -name '*dist-manifest.json' | sort
)
[ "${#manifests[@]}" -gt 0 ] || die "no *dist-manifest.json under $dir"

jqm() { jq -s "$@" "${manifests[@]}"; }

# Version and tag. `plan` and every per-target build manifest agree on these;
# disagreement means we are mixing artifacts from two different runs.
# shellcheck disable=SC2016  # $app is a jq variable, not a shell one.
version=$(jqm -r --arg app "$APP" '
  [ .[].releases[]? | select(.app_name == $app) | .app_version ] | unique
  | if length == 1 then .[0] else "" end')
[ -n "$version" ] || die "could not resolve a single $APP version from the manifests"

tag=$(jqm -r '[ .[].announcement_tag? | select(. != null) ] | unique
  | if length == 1 then .[0] else "" end')
[ -n "$tag" ] || die "could not resolve a single announcement_tag from the manifests"
# The url below writes the tag as "v#{version}", so the two must agree. If the
# tagging convention ever changes, this fails loudly rather than 404ing.
[ "$tag" = "v$version" ] || die "tag '$tag' is not 'v$version'; url template would be wrong"

# ---------------------------------------------------------------------------
# Archive name + sha256 per target, straight out of the manifests.
#
# Field names verified against cargo-dist 0.32.0: `dist manifest-schema` defines
# Artifact.checksums as "keys are the name of an algorithm like sha256, values
# are the actual hex string", and a real `dist build --output-format=json`
# populates artifacts["<name>"].checksums.sha256. `dist plan` does NOT (nothing
# is built yet), which is why only entries carrying a checksum are accepted
# here: it means the plan manifest can sit in the same directory harmlessly.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2016  # $app/$mine/$k are jq variables, not shell ones.
rows=$(jqm -r --arg app "$APP" '
  ( [ .[].releases[]? | select(.app_name == $app) | .artifacts[]? ] | unique ) as $mine
  | [ .[].artifacts? | select(. != null) | to_entries[] ]
  | map(select(.key as $k | $mine | index($k)))
  | map(select(.value.kind == "executable-zip"))
  | map(select(.value.checksums.sha256 != null))
  | map({
      triple: (.value.target_triples | first),
      name:   .value.name,
      sha:    .value.checksums.sha256,
      exes:   [ .value.assets[]? | select(.kind == "executable") | .name ] | sort
    })
  | unique
  | .[] | [ .triple, .name, .sha, (.exes | join(",")) ] | @tsv')
[ -n "$rows" ] || die "no checksummed $APP archives in the manifests (built artifacts missing?)"

lookup() { printf '%s\n' "$rows" | awk -F'\t' -v t="$1" '$1 == t'; }

# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
emit_target() {
  local triple=$1 indent=$2
  local row name sha manifest_exes archive staged tops exes exe

  row=$(lookup "$triple")
  [ -n "$row" ] || die "no archive for $triple"
  [ "$(printf '%s\n' "$row" | wc -l)" -eq 1 ] ||
    die "conflicting archives for $triple (mixed artifacts from two runs?)"

  name=$(printf '%s' "$row" | cut -f2)
  sha=$(printf '%s' "$row" | cut -f3)
  manifest_exes=$(printf '%s' "$row" | cut -f4 | tr ',' '\n' | grep -v '^$' | sort)

  # cargo-dist archives unpack into a directory, unlike the flat goreleaser
  # tarballs the previous cask consumed, so every `binary` path needs that
  # prefix. Read it off the archive rather than trusting the naming rule.
  archive="$dir/$name"
  [ -f "$archive" ] || die "archive $name is not in $dir (needed to verify its layout)"
  tops=$(tar -tf "$archive" | sed 's#/.*##' | sort -u)
  [ "$(printf '%s\n' "$tops" | wc -l)" -eq 1 ] ||
    die "$name has more than one top-level entry: $tops"
  staged=$tops
  [ "$staged" = "${name%.tar.xz}" ] ||
    die "$name unpacks into '$staged', not '${name%.tar.xz}'"

  # Every executable in the archive gets symlinked, not just `rvl`. The
  # retrievers (cindex, rustindex, goindex) are found by looking NEXT TO the
  # running binary, and on macOS std::env::current_exe() returns the path used
  # to exec — the symlink in Homebrew's bin, not the Caskroom original. Link
  # only `rvl` and its neighbours are invisible, so Rust/C/Go scanning quietly
  # degrades to "no retriever" for every brew user.
  #
  # Taken from the archive so that files packed via `include` (goindex, which
  # is a Go build and therefore not a cargo-dist "executable" asset) are
  # covered too, then checked against the manifest so a dropped Rust binary
  # still fails the release.
  exes=$(tar -tvf "$archive" | awk '$1 ~ /^-/ && $1 ~ /x/ { print $NF }' |
    sed "s#^$staged/##" | grep -v '/' | sort -u)
  [ -n "$exes" ] || die "$name contains no executable files"
  while IFS= read -r exe; do
    [ -n "$exe" ] || continue
    printf '%s\n' "$exes" | grep -qx "$exe" ||
      die "$name is missing '$exe', which the manifest lists as an executable"
  done <<<"$manifest_exes"
  printf '%s\n' "$exes" | grep -qx "$CASK_TOKEN" ||
    die "$name does not contain the $CASK_TOKEN binary itself"

  printf '%ssha256 "%s"\n' "$indent" "$sha"
  # Only the tag is interpolated; the filename is cargo-dist's and carries no
  # version, so it is written out literally.
  printf '%surl "https://github.com/%s/releases/download/v#{version}/%s"\n' \
    "$indent" "$RELEASE_REPO" "$name"
  # `rvl` first, then the retrievers, for readability.
  printf '%sbinary "%s/%s"\n' "$indent" "$staged" "$CASK_TOKEN"
  while IFS= read -r exe; do
    [ "$exe" = "$CASK_TOKEN" ] && continue
    printf '%sbinary "%s/%s"\n' "$indent" "$staged" "$exe"
  done <<<"$exes"
}

emit_os_block() {
  local os_block=$1 intel=$2 arm=$3
  printf '  %s do\n' "$os_block"
  printf '    on_intel do\n'
  emit_target "$intel" "      "
  printf '    end\n'
  printf '    on_arm do\n'
  emit_target "$arm" "      "
  printf '    end\n'
  printf '  end\n'
}

# Fail before writing a single line if any target is missing.
for triple in $TRIPLES; do
  triple_blocks "$triple" >/dev/null || die "unmapped target triple $triple"
  [ -n "$(lookup "$triple")" ] || die "release is missing target $triple"
done

cat <<EOF
# This file is generated on release by revelara-ai/rvl-cli
# (.github/workflows/publish-cask.yml -> ci/render-cask.sh). DO NOT EDIT.
#
# It is written from that release's cargo-dist dist-manifest.json. Editing it
# here is pointless: the next tag overwrites the file wholesale.
cask "$CASK_TOKEN" do
  version "$version"

EOF
emit_os_block on_macos x86_64-apple-darwin aarch64-apple-darwin
printf '\n'
emit_os_block on_linux x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
cat <<EOF

  name "$CASK_NAME"
  desc "$CASK_DESC"
  homepage "$CASK_HOMEPAGE"

  livecheck do
    skip "Auto-generated on release."
  end

  postflight do
    if OS.mac?
      system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "#{staged_path}"]
    end
  end

  # No zap stanza required

end
EOF
