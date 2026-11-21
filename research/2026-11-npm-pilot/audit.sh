#!/usr/bin/env bash
d=repos/${1//\//__}; out=$PWD/audits/${1//\//__}.json
(cd "$d" && timeout 180 npm audit --json --package-lock-only --ignore-scripts > "$out" 2>/dev/null)
