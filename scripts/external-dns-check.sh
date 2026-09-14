#!/usr/bin/env bash
#
# external-dns-check.sh
#
# Pokreni OVO SA DRUGE MASINE (ne sa samog Hetzner servera), NAKON sto
# namerno otvoris port 53, da potvrdis da server NIKAD ne odgovara na
# imena van sopstvene test zone. Ovo je direktan regresioni test za
# BSI/CERT-Bund incident opisan u README.
#
# Upotreba:
#   ./external-dns-check.sh <SERVER_IP>

set -euo pipefail

SERVER_IP="${1:-}"

if [ -z "$SERVER_IP" ]; then
  echo "Upotreba: $0 <SERVER_IP>"
  exit 2
fi

FAIL=0

check_refused() {
  local domain="$1"
  local proto="$2" # udp ili tcp
  local extra_flag=""
  [ "$proto" = "tcp" ] && extra_flag="+tcp"

  echo "--- dig $extra_flag $domain @$SERVER_IP ---"
  local output
  output=$(dig $extra_flag "$domain" @"$SERVER_IP" +time=5 +tries=1 2>&1) || true
  echo "$output"

  if ! echo "$output" | grep -q "status: REFUSED"; then
    echo "FAIL: ocekivan status REFUSED za $domain ($proto)"
    FAIL=1
  fi

  if echo "$output" | grep -qE "flags:.*\bra\b"; then
    echo "FAIL: server postavlja 'ra' (recursion available) flag - ovo NE SME da se desi"
    FAIL=1
  fi

  if echo "$output" | grep -q "ANSWER: 0"; then
    : # ocekivano
  else
    echo "FAIL: ocekivan ANSWER: 0 za $domain ($proto)"
    FAIL=1
  fi

  echo ""
}

echo "=== BSI regresioni test: van-zonski upiti MORAJU biti REFUSED ==="
echo ""

check_refused "google.com" "udp"
check_refused "cert-bund.de" "udp"
check_refused "example.com" "udp"
check_refused "$(head -c 8 /dev/urandom | xxd -p).random-test.invalid" "udp"
check_refused "cert-bund.de" "tcp"

if [ "$FAIL" -eq 0 ]; then
  echo "PASS: server odbija (REFUSED, bez RA) sve van-zonske upite u ovom testu."
else
  echo "FAIL: bar jedan test nije prosao. NE otvaraj/ostavljaj port 53 javno dok se ovo ne resi."
  exit 1
fi
