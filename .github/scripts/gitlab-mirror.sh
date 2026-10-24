#!/usr/bin/env bash
# gitlab-mirror.sh — copy this public repository's main branch (and its new tags) to the GitLab copy, refusing anything
# that would make the GitLab copy lose what it already has. DP 2026-10-23: "make sure that if the information is an empty
# set in github, gitlab is not overwritten with the empty set."
#
#   gitlab-mirror.sh <gitlab-https-url> [<branch>]      (the token comes from $GITLAB_PUSH_TOKEN, never an argument)
#
# The guards, in order — any one failing stops the run (exit 1) and NOTHING is pushed:
#   1. the local branch exists and has commits, and the checkout is a full history (not shallow);
#   2. the local tree is not empty and carries the repository's own anchor files (README.md, LICENSE);
#   3. GitLab's current head (when GitLab has one) is an ANCESTOR of ours — the push is a plain fast-forward; a rewritten
#      or replaced history on GitHub never reaches GitLab;
#   4. the tracked-file count does not fall below 80 % of GitLab's — a mass deletion committed normally (still a
#      fast-forward) is refused too;
#   then a PLAIN push of the branch (never --force, never --mirror — a mirror push deletes refs GitHub lacks) and of the
#   tags GitLab does not have (existing tags are never moved). GitLab's own branch protection (force push off, the default
#   on a protected main) is the server-side backstop for all of this.
set -euo pipefail
URL="${1:?usage: gitlab-mirror.sh <gitlab-https-url> [branch]}"
BR="${2:-main}"
MIN_KEEP_PCT="${MIN_KEEP_PCT:-80}"
: "${GITLAB_PUSH_TOKEN:?GITLAB_PUSH_TOKEN is not set (a GitHub Actions secret)}"
AUTH="Authorization: Basic $(printf 'oauth2:%s' "$GITLAB_PUSH_TOKEN" | base64 | tr -d '\n')"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
g() { git -c credential.helper= -c "http.extraheader=$AUTH" "$@"; }
say() { echo "gitlab-mirror: $*"; }
stop() { echo "::error title=gitlab-mirror::$*"; say "STOPPED — nothing pushed: $*"; exit 1; }

# 1
[ "$(git rev-parse --is-shallow-repository)" = "false" ] || stop "the checkout is shallow (fetch-depth must be 0)"
git rev-parse --verify -q "refs/heads/$BR^{commit}" >/dev/null || git rev-parse --verify -q "origin/$BR^{commit}" >/dev/null || stop "no local $BR branch"
OURS=$(git rev-parse --verify -q "refs/heads/$BR^{commit}" || git rev-parse "origin/$BR^{commit}")
NC=$(git rev-list --count "$OURS")
[ "$NC" -ge 1 ] || stop "$BR has no commits"
# 2
NF=$(git ls-tree -r --name-only "$OURS" | wc -l)
[ "$NF" -ge 1 ] || stop "$BR's tree is empty"
for f in README.md LICENSE; do git cat-file -e "$OURS:$f" 2>/dev/null || stop "$BR lacks $f — not this repository's tree"; done
say "ours: $BR $OURS — $NC commits, $NF files"
# 3 + 4
THEIRS=""
if g ls-remote --exit-code --heads "$URL" "$BR" >"$T/remote.txt" 2>/dev/null; then
  THEIRS=$(cut -f1 "$T/remote.txt" | head -1)
  g fetch -q "$URL" "refs/heads/$BR:refs/remotes/gitlab/$BR" || stop "could not fetch GitLab's $BR"
  if [ "$THEIRS" = "$OURS" ]; then say "GitLab already at $OURS — branch unchanged"; else
    git merge-base --is-ancestor "$THEIRS" "$OURS" || stop "GitLab's $BR ($THEIRS) is not an ancestor of ours — GitHub's history was rewritten or replaced; GitLab keeps its copy"
    TF=$(git ls-tree -r --name-only "$THEIRS" | wc -l)
    [ $((NF * 100)) -ge $((TF * MIN_KEEP_PCT)) ] || stop "ours has $NF files, GitLab's $TF — more than $((100 - MIN_KEEP_PCT)) % would disappear"
    say "GitLab: $THEIRS ($TF files) → a fast-forward of $(git rev-list --count "$THEIRS..$OURS") commit(s)"
  fi
else
  say "GitLab has no $BR yet — the first copy"
fi
# the push — plain, no force
if [ "$THEIRS" != "$OURS" ]; then g push "$URL" "$OURS:refs/heads/$BR"; fi
# tags GitLab lacks, one by one, never moved
g ls-remote --tags "$URL" | awk '{print $2}' | sed 's#refs/tags/##; s#\^{}##' | sort -u > "$T/tags.txt"
NEW=0
for t in $(git tag --list); do
  grep -qx "$t" "$T/tags.txt" && continue
  g push "$URL" "refs/tags/$t:refs/tags/$t" && NEW=$((NEW + 1))
done
say "done — $BR at $OURS on GitLab; $NEW new tag(s)"
