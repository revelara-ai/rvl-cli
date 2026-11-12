#!/bin/sh
# Check out each repository of the RC-027 answer key at its pinned commit,
# under <dir>/<owner>/<name>, for examples/rc027_key.rs to score.
#
#     fetch.sh <dir> [key.jsonl]
#
# A checkout already at its commit is kept; one at another commit is moved
# to the pinned commit. Each fetch is one commit deep.
set -eu
dir=${1:?usage: fetch.sh <dir> [key.jsonl]}
key=${2:-$(dirname "$0")/key.jsonl}
sed -n 's/.*"repo": *"\([^"]*\)", *"commit": *"\([0-9a-f]\{40\}\)".*/\1 \2/p' "$key" |
while read -r repo commit; do
	d=$dir/$repo
	if [ "$(git -C "$d" rev-parse HEAD 2>/dev/null)" = "$commit" ]; then
		continue
	fi
	mkdir -p "$d"
	git -C "$d" init -q
	git -C "$d" fetch -q --depth 1 "https://github.com/$repo" "$commit"
	git -C "$d" checkout -q --force FETCH_HEAD
	echo "$repo $commit"
done
