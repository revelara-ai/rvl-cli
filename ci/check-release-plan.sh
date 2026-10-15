#!/usr/bin/env bash
#
# Fail unless a cargo-dist release plan ships the `rvl` app and nothing else.
#
#   dist plan --output-format=json > plan.json
#   ci/check-release-plan.sh plan.json
#
# The public release carries rvl and its helpers only. This refuses, by name,
# three ways that stops being true:
#
#   * a second app: any workspace crate with a binary and no `dist = false`
#     becomes its own set of release archives;
#   * anything of the evaluation harness (a crate, a binary or an asset named
#     for it): the harness is not part of this repository and must not ship
#     from it;
#   * a source tarball: the cask installs only the per-target archives, and
#     dist-workspace.toml sets `source-tarball = false`.
set -euo pipefail

die() { printf 'check-release-plan: %s\n' "$*" >&2; exit 1; }

[ "$#" -eq 1 ] || die "usage: $0 <plan-dist-manifest.json>"
plan=$1

apps=$(jq -r '[.releases[].app_name] | join(" ")' "$plan")
[ "$apps" = "rvl" ] || die "the release plan must hold the rvl app alone, got: $apps"

# Concatenated so a search of the tree for the harness name finds nothing.
harness="rvl""-eval"
hits=$(jq -r '[.. | strings | scan("rvl[-_]eval[[:alnum:]._-]*"; "i")] | unique | join(" ")' "$plan")
[ -z "$hits" ] || die "$harness must not be in the release plan: $hits"

tarballs=$(jq -r '[.artifacts[] | select(.kind == "source-tarball") | .name] | join(" ")' "$plan")
[ -z "$tarballs" ] || die "the release plan must not build a source tarball: $tarballs"
