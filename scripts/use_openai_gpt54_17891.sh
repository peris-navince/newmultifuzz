#!/usr/bin/env bash
set -euo pipefail

export HTTP_PROXY=http://127.0.0.1:17891
export HTTPS_PROXY=http://127.0.0.1:17891
export http_proxy=http://127.0.0.1:17891
export https_proxy=http://127.0.0.1:17891
export ALL_PROXY=http://127.0.0.1:17891
export all_proxy=http://127.0.0.1:17891
export OPENAI_MODEL=gpt-5.4

echo "[CHECK] proxy:"
env | grep -i proxy || true

echo "[CHECK] tunnel 17891:"
ss -ltnp | grep 17891 || {
  echo "[ERROR] 127.0.0.1:17891 is not listening."
  echo "[HINT] On Windows, run: ssh -N wgh-gpt"
  return 1 2>/dev/null || exit 1
}

echo "[CHECK] GPT-5.4:"
curl -sS \
  --connect-timeout 30 \
  --max-time 300 \
  -w '\nHTTP_CODE=%{http_code}\nTOTAL_TIME=%{time_total}\n' \
  https://api.openai.com/v1/responses \
  -H "Authorization: Bearer ${OPENAI_API_KEY:?OPENAI_API_KEY missing}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-5.4",
    "input": "Reply with exactly: ping",
    "max_output_tokens": 20
  }' | tee /tmp/openai_gpt54_preflight.txt

grep -q 'HTTP_CODE=200' /tmp/openai_gpt54_preflight.txt || {
  echo "[ERROR] GPT-5.4 preflight failed. Do not run MultiFuzz."
  return 1 2>/dev/null || exit 1
}

echo "[OK] GPT-5.4 ready through 17891."
