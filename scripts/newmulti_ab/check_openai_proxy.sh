#!/usr/bin/env bash
set -u

echo "== proxy env =="
env | grep -i proxy || true

echo
echo "== port 17890 =="
if ! ss -lntp | grep -E ':17890\b'; then
  echo "[FAIL] 127.0.0.1:17890 is not listening"
  exit 1
fi

echo
echo "== OpenAI API =="
curl -sS --connect-timeout 20 --max-time 60 \
  https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  > /tmp/openai_models_check.json || {
    echo "[FAIL] OpenAI API check failed"
    exit 1
  }

head -c 300 /tmp/openai_models_check.json
echo
echo "[OK] OpenAI proxy/API reachable"
