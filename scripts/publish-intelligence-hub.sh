#!/usr/bin/env bash
# SENTINEL APEX Intelligence Hub — race-safe, fail-closed generated content publisher.
# Use ONLY in an ephemeral GitHub Actions checkout; never against an operator workspace.
# No Cloudflare API/Worker/D1 calls, no force push, no non-FF history changes.
set -euo pipefail

if [[ "\${GITHUB_ACTIONS:-}" != "true" || -z "\${GITHUB_WORKSPACE:-}" ||
      "$(pwd -P)" != "$(cd "$GITHUB_WORKSPACE" && pwd -P)" ]]; then
  echo "::error title=Unsafe Publishing Context::Only the ephemeral GitHub Actions checkout is permitted."
  exit 1
fi
if [[ "$(git symbolic-ref --quiet --short HEAD)" != "main" ]]; then
  echo "::error title=Unsafe Publishing Branch::Expected checkout of main."
  exit 1
fi

readonly MAX_ATTEMPTS=3
readonly GENERATED_PATHS=(
  vendor/ timeline/ collections/ detections/live-feed.html
  threat/index.html api/intel/vendors.json api/intel/vendor/
  api/intel/timeline.json api/intel/collections.json
  api/intel/detections-library.json sitemap.xml
)

check_outputs() {
  for output in \
    vendor/index.html timeline/index.html collections/index.html \
    detections/live-feed.html threat/index.html api/intel/vendors.json \
    api/intel/timeline.json api/intel/collections.json \
    api/intel/detections-library.json; do
    if [[ ! -s "$output" ]]; then
      echo "::error title=Intelligence Hub Output Missing::Required generated artifact absent/empty: $output"
      exit 1
    fi
  done
  if [[ -f sitemap.xml ]] && command -v xmllint >/dev/null 2>&1; then
    xmllint --noout sitemap.xml
  fi
}

stage_commit_if_changed() {
  git add -- "\${GENERATED_PATHS[@]}"
  if git diff --cached --quiet; then
    echo "PASS: latest main already contains equivalent generated outputs; nothing to publish."
    return 1
  fi
  git commit -m "SENTINEL APEX — Regenerate intelligence hub against reviewed main [skip ci]"
  return 0
}

# The calling workflow generated/validated outputs before entry. Revalidate
# here, including the initial attempt. All retries use the LATEST code/data.
check_outputs
git config user.name "CYBERDUDEBIVASH"
git config user.email "bivash@cyberdudebivash.com"
stage_commit_if_changed || exit 0

for ((attempt=1; attempt<=MAX_ATTEMPTS; attempt++)); do
  if git push origin HEAD:refs/heads/main; then
    echo "PASS: Intelligence Hub published by fast-forward push (attempt $attempt)."
    exit 0
  fi
  if (( attempt == MAX_ATTEMPTS )); then
    echo "::error title=Intelligence Hub Publish Failed::Maximum $MAX_ATTEMPTS attempts reached. No force push."
    exit 1
  fi

  local_base="$(git rev-parse HEAD^)"
  if [[ -n "$(git status --porcelain)" ]]; then
    echo "::error title=Intelligence Hub Dirty Checkout::Unsafe to replace local checkout."
    exit 1
  fi
  git fetch --no-tags origin refs/heads/main
  remote_head="$(git rev-parse FETCH_HEAD)"
  if [[ "$remote_head" == "$local_base" ]]; then
    echo "::error title=Intelligence Hub Push Denied::Remote did not advance; refusing futile retries."
    exit 1
  fi
  if ! git merge-base --is-ancestor "$local_base" "$remote_head"; then
    echo "::error title=Intelligence Hub History Diverged::Manual operator review required."
    exit 1
  fi

  # Hard reset is permitted ONLY in the short-lived, clean GitHub Actions
  # checkout. Unlike 'git pull --rebase', no stale generated JSON replay.
  git reset --hard "$remote_head"
  node --check generate-intelligence-hub.js
  node --check api/_lib/intelligence-hub.js
  node --test tests-js/intelligence-hub.test.js
  node generate-intelligence-hub.js
  check_outputs
  stage_commit_if_changed || exit 0
done
