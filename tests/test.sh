#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
SOURCE="$PWD/ipt-inbound-guard.sh"
bash -n "$SOURCE"
sh -n install.sh
source <(sed '/^case "${1:-menu}" in$/,$d' "$SOURCE")
need_root() { :; }
TEMP="$(mktemp -d)"
trap 'rm -rf "$TEMP"' EXIT
CONF_DIR="$TEMP"
RULE_FILE="$TEMP/rules.db"
INTERVAL_FILE="$TEMP/interval.conf"
SIGNATURE_FILE="$TEMP/last_applied.sha256"
LAST_REFRESH_FILE="$TEMP/last_refresh"
REFRESH_LOCK_FILE="$TEMP/refresh.lock"
HOOKS="$TEMP/hooks"
COUNT="$TEMP/apply_count"
touch "$RULE_FILE"
assert_eq() { [[ "$1" == "$2" ]] || { echo "ASSERT FAIL $3: expected=$2 got=$1" >&2; exit 1; }; }
assert_eq "$(get_interval)" "1" "default 1 minute"
echo 5 > "$INTERVAL_FILE"
assert_eq "$(get_interval)" "5" "custom interval"
echo 08 > "$INTERVAL_FILE"
assert_eq "$(get_interval)" "8" "leading-zero decimal interval"
echo abc > "$INTERVAL_FILE"
assert_eq "$(get_interval)" "1" "invalid interval"
rm "$INTERVAL_FILE"
valid_ports 80
valid_ports "80,443,10000:20000"
for bad in 0 65536 "100:99"; do
  if valid_ports "$bad"; then echo "Accepted invalid port: $bad" >&2; exit 1; fi
done
resolve_v4() { printf '%s\n' "$DNS_TEST_IP"; }
resolve_v6() { :; }
ipt4() { [[ "$1" == "-C" ]] && [ -f "$HOOKS" ]; }
ipt6() { [[ "$1" == "-C" ]] && [ -f "$HOOKS" ]; }
apply_rules() {
  echo APPLY >> "$COUNT"
  touch "$HOOKS"
  rules_signature > "$SIGNATURE_FILE"
}
printf 'id-1|1|allow|tcp|443|example.invalid|test\n' > "$RULE_FILE"
export DNS_TEST_IP=203.0.113.1
refresh_if_due
assert_eq "$(wc -l < "$COUNT")" 1 "initial apply"
echo 0 > "$LAST_REFRESH_FILE"
refresh_if_due
assert_eq "$(wc -l < "$COUNT")" 1 "no rebuild on unchanged DNS"
echo 0 > "$LAST_REFRESH_FILE"
export DNS_TEST_IP=203.0.113.2
refresh_if_due
assert_eq "$(wc -l < "$COUNT")" 2 "rebuild on changed DDNS"
echo 0 > "$LAST_REFRESH_FILE"
resolve_v4() { :; }
if refresh_if_due >/dev/null 2>&1; then echo "DNS failure incorrectly succeeded" >&2; exit 1; fi
assert_eq "$(wc -l < "$COUNT")" 2 "preserve firewall on DNS failure"
rm -f "$HOOKS"
echo 0 > "$LAST_REFRESH_FILE"
resolve_v4() { printf '%s\n' "$DNS_TEST_IP"; }
refresh_if_due
assert_eq "$(wc -l < "$COUNT")" 3 "restore missing firewall hooks"
echo "PASS: syntax, default 1min, interval, ports, DNS hash, failures, hooks"
