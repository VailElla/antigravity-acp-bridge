#!/bin/sh
# The existing authenticated SSH channel is the only writer. The directory is
# root-only, and each heartbeat replaces the file atomically.
set -eu
umask 077
dir=/tmp/antigravity-port-feed
mkdir -p "$dir"
chmod 700 "$dir"
tmp="$dir/.feed.$$"
trap 'rm -f "$tmp"' EXIT HUP INT TERM
while IFS= read -r line; do
  [ "${#line}" -le 8192 ] || continue
  printf '%s\n' "$line" > "$tmp"
  mv -f "$tmp" "$dir/current.json"
done
