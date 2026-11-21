#!/usr/bin/env bash
# fetch.sh REPO BRANCH: package.json + package-lock.json at the root, if present
r=$1; b=$2; d=repos/${r//\//__}
code=$(curl -s -o /dev/null -w "%{http_code}" -I "https://raw.githubusercontent.com/$r/$b/package-lock.json")
[ "$code" = 200 ] || exit 0
mkdir -p "$d"
curl -sfo "$d/package.json" "https://raw.githubusercontent.com/$r/$b/package.json" &&
curl -sfo "$d/package-lock.json" "https://raw.githubusercontent.com/$r/$b/package-lock.json" && echo "$r"
