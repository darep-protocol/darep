#!/bin/sh
# Check the actual branch history, including the initial publication commit.
set -eu
failed=0
for commit in $(git rev-list HEAD); do
  if ! git show -s --format=%B "$commit" | git interpret-trailers --parse |
      grep -Eq '^Signed-off-by: .+ <[^<>[:space:]]+@[^<>[:space:]]+>$'; then
    echo "Missing DCO Signed-off-by trailer: $commit" >&2
    failed=1
  fi
done
if [ "$failed" -ne 0 ]; then exit 1; fi
echo "DCO: all commits have a Signed-off-by trailer"
