#!/bin/sh
# Require a pull request with a green "CI passed" check before anything lands on main.
# Usage: deploy/protect-main.sh owner/repo
set -eu
repo=${1:?usage: $0 owner/repo}
gh api -X POST "repos/$repo/rulesets" --input "$(dirname "$0")/ruleset-main.json" --jq '"Ruleset \(.name) created: \(._links.html.href)"'
