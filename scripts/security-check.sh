#!/usr/bin/env bash
#
# security-check.sh
#
# Pokreni OVO LOKALNO NA SERVERU dok je aplikacija upaljena i DOK JE PORT 53
# JOS UVEK BLOKIRAN prema javnom internetu (ufw deny 53/udp, 53/tcp).
# Cilj: uhvatiti ocigledne probleme PRE nego sto uopste razmatras da
# otvoris port javno.
#
# Ovo NIJE zamena za scripts/external-dns-check.sh (koji mora da se
# pokrene SA DRUGE MASINE nakon otvaranja porta).

set -uo pipefail

HTTP_URL="${1:-http://127.0.0.1:3000}"
DNS_HOST="${2:-127.0.0.1}"
FAIL=0

echo "=== 1) HTTP: healthz dostupan ==="
if curl -sf "$HTTP_URL/healthz" > /dev/null; then
  echo "OK"
else
  echo "FAIL: /healthz nije dostupan na $HTTP_URL"
  FAIL=1
fi

echo ""
echo "=== 2) HTTP: kreiranje sesije BEZ prihvatanja privacy/terms mora biti 400 ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$HTTP_URL/api/tests" \
  -H "Content-Type: application/json" -d '{}')
if [ "$STATUS" = "400" ]; then
  echo "OK (400)"
else
  echo "FAIL: ocekivan 400, dobijen $STATUS - server-side enforcement NE RADI"
  FAIL=1
fi

echo ""
echo "=== 3) HTTP: kreiranje sesije SA prihvatanjem mora uspeti (200) ==="
RESP=$(curl -s -X POST "$HTTP_URL/api/tests" \
  -H "Content-Type: application/json" \
  -d '{"privacyAcknowledged":true,"termsAccepted":true}')
echo "$RESP"
TEST_ID=$(echo "$RESP" | grep -o '"testId":"[a-f0-9]*"' | cut -d'"' -f4)
RESULT_TOKEN=$(echo "$RESP" | grep -o '"resultToken":"[a-f0-9]*"' | cut -d'"' -f4)
DNS_DOMAIN=$(echo "$RESP" | grep -o '"dnsTestDomain":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TEST_ID" ] || [ -z "$RESULT_TOKEN" ]; then
  echo "FAIL: nije moguce izvuci testId/resultToken iz odgovora"
  FAIL=1
else
  echo "OK (testId=$TEST_ID resultToken=$RESULT_TOKEN)"
fi

echo ""
echo "=== 4) DNS lokalno (udp): validan probe za aktivnu sesiju treba da vrati NOERROR/A ==="
if [ -n "$TEST_ID" ] && [ -n "$DNS_DOMAIN" ]; then
  PROBE="aaaa1111.${TEST_ID}.${DNS_DOMAIN}"
  OUT=$(dig "@$DNS_HOST" -p 53 "$PROBE" A +time=3 +tries=1 2>&1)
  echo "$OUT"
  if echo "$OUT" | grep -q "status: NOERROR"; then
    echo "OK"
  else
    echo "FAIL: ocekivan NOERROR za validan probe"
    FAIL=1
  fi
else
  echo "PRESKOCENO (nema testId/domain iz prethodnog koraka)"
fi

echo ""
echo "=== 5) DNS lokalno (udp): nasumican van-zonski upit MORA biti REFUSED ==="
OUT=$(dig "@$DNS_HOST" -p 53 "cert-bund.de" A +time=3 +tries=1 2>&1)
echo "$OUT"
if echo "$OUT" | grep -q "status: REFUSED"; then
  echo "OK"
else
  echo "FAIL: ovo je TACNO ona vrsta greske koja je izazvala prethodni incident. NE nastavljaj dok se ne resi."
  FAIL=1
fi

echo ""
echo "=== 6) DNS lokalno (udp): nepoznat/izmisljen testId u nasoj zoni mora biti NXDOMAIN ==="
if [ -n "$DNS_DOMAIN" ]; then
  OUT=$(dig "@$DNS_HOST" -p 53 "probe.deadbeefdeadbeefdeadbeefdeadbeef.${DNS_DOMAIN}" A +time=3 +tries=1 2>&1)
  echo "$OUT"
  if echo "$OUT" | grep -q "status: NXDOMAIN"; then
    echo "OK"
  else
    echo "FAIL: ocekivan NXDOMAIN za nepostojeci testId"
    FAIL=1
  fi
fi

echo ""
echo "=== 7) HTTP: brisanje sesije ==="
if [ -n "$RESULT_TOKEN" ]; then
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$HTTP_URL/api/tests/$RESULT_TOKEN")
  if [ "$STATUS" = "204" ]; then
    echo "OK"
  else
    echo "FAIL: ocekivan 204, dobijen $STATUS"
    FAIL=1
  fi
fi

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "PASS: lokalne provere prosle. I dalje pokreni scripts/external-dns-check.sh SA DRUGE MASINE pre nego sto proglasis test zavrsenim."
else
  echo "FAIL: bar jedna provera nije prosla - NE otvaraj port 53 javno."
  exit 1
fi
