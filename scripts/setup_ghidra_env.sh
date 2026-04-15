#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(pwd)}"
VENV_PATH="${VENV_PATH:-$REPO_ROOT/extractor/.venv}"
GHIDRA_HOME="${GHIDRA_HOME:-$REPO_ROOT/tools/ghidra}"
USER_JDK_HOME="${USER_JDK_HOME:-$HOME/tools/jdk-21}"
REQUIREMENTS_FILE="${REQUIREMENTS_FILE:-$REPO_ROOT/requirements-ghidra.txt}"
INSTALL_PY_DEPS=0
INSTALL_USER_JDK=0

usage() {
  cat <<EOF
Usage: bash scripts/setup_ghidra_env.sh [--install-py-deps] [--install-user-jdk]

Checks and optionally installs the Ghidra Python toolchain requirements.

Environment variables:
  REPO_ROOT           Repository root. Default: current directory
  VENV_PATH           Python venv path. Default: \$REPO_ROOT/extractor/.venv
  GHIDRA_HOME         Ghidra install path. Default: \$REPO_ROOT/tools/ghidra
  USER_JDK_HOME       User-local JDK 21 path. Default: \$HOME/tools/jdk-21
  REQUIREMENTS_FILE   Python requirements file. Default: \$REPO_ROOT/requirements-ghidra.txt
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-py-deps) INSTALL_PY_DEPS=1; shift ;;
    --install-user-jdk) INSTALL_USER_JDK=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[ERROR] Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

major_from_java_version() {
  local text="$1"
  local ver
  ver=$(printf '%s\n' "$text" | sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -n1)
  if [[ -z "$ver" ]]; then echo ""; return; fi
  if [[ "$ver" == 1.* ]]; then
    echo "$ver" | cut -d. -f2
  else
    echo "$ver" | sed 's/[.+_-].*//'
  fi
}

check_java21() {
  if ! command -v java >/dev/null 2>&1; then
    echo "[WARN] java not found in PATH"
    return 1
  fi
  local out major
  out=$(java -version 2>&1 || true)
  major=$(major_from_java_version "$out")
  echo "[INFO] java path: $(command -v java)"
  echo "$out" | sed 's/^/[INFO] /'
  if [[ -n "$major" && "$major" -ge 21 ]]; then
    echo "[OK] JDK 21+ is active"
    return 0
  fi
  echo "[WARN] Active Java is not JDK 21+"
  return 1
}

install_user_jdk() {
  echo "[INFO] Installing Temurin JDK 21 under: $USER_JDK_HOME"
  mkdir -p "$(dirname "$USER_JDK_HOME")"
  local tmp
  tmp=$(mktemp -d)
  echo "[INFO] Downloading JDK 21 archive..."
  if command -v wget >/dev/null 2>&1; then
    wget -O "$tmp/temurin21.tar.gz" "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse"
  elif command -v curl >/dev/null 2>&1; then
    curl -L -o "$tmp/temurin21.tar.gz" "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse"
  else
    echo "[ERROR] Neither wget nor curl is available. Please download Temurin JDK 21 manually." >&2
    exit 1
  fi
  rm -rf "$USER_JDK_HOME"
  mkdir -p "$USER_JDK_HOME"
  tar -xzf "$tmp/temurin21.tar.gz" -C "$USER_JDK_HOME" --strip-components=1
  rm -rf "$tmp"
  echo "[OK] JDK installed at: $USER_JDK_HOME"
}

if ! check_java21; then
  if [[ -x "$USER_JDK_HOME/bin/java" ]]; then
    echo "[INFO] Trying user JDK: $USER_JDK_HOME"
    export JAVA_HOME="$USER_JDK_HOME"
    export PATH="$JAVA_HOME/bin:$PATH"
  elif [[ "$INSTALL_USER_JDK" -eq 1 ]]; then
    install_user_jdk
    export JAVA_HOME="$USER_JDK_HOME"
    export PATH="$JAVA_HOME/bin:$PATH"
  else
    cat <<EOF
[ERROR] Ghidra 12.x requires JDK 21+, but it is not active.

No root required option:
  bash scripts/setup_ghidra_env.sh --install-user-jdk

Or manually:
  export JAVA_HOME=$USER_JDK_HOME
  export PATH="\$JAVA_HOME/bin:\$PATH"
EOF
    exit 1
  fi
  check_java21 || exit 1
fi

if [[ ! -x "$GHIDRA_HOME/support/pyghidraRun" ]]; then
  echo "[ERROR] pyghidraRun not found: $GHIDRA_HOME/support/pyghidraRun" >&2
  exit 1
fi
if [[ ! -x "$GHIDRA_HOME/support/analyzeHeadless" ]]; then
  echo "[ERROR] analyzeHeadless not found: $GHIDRA_HOME/support/analyzeHeadless" >&2
  exit 1
fi
echo "[OK] Ghidra launchers found under: $GHIDRA_HOME/support"

if [[ ! -d "$VENV_PATH" ]]; then
  echo "[ERROR] Python venv not found: $VENV_PATH" >&2
  exit 1
fi
# shellcheck disable=SC1090
source "$VENV_PATH/bin/activate"

echo "[INFO] Python: $(which python3)"
python3 --version | sed 's/^/[INFO] /'

if python3 - <<'PY'
import pyghidra, jpype, packaging
print('pyghidra import ok')
PY
then
  echo "[OK] Python Ghidra dependencies are importable"
else
  if [[ "$INSTALL_PY_DEPS" -eq 1 ]]; then
    if [[ ! -f "$REQUIREMENTS_FILE" ]]; then
      echo "[ERROR] requirements file not found: $REQUIREMENTS_FILE" >&2
      exit 1
    fi
    echo "[INFO] Installing Python dependencies from: $REQUIREMENTS_FILE"
    pip install -r "$REQUIREMENTS_FILE"
    python3 - <<'PY'
import pyghidra, jpype, packaging
print('pyghidra import ok')
PY
    echo "[OK] Python Ghidra dependencies installed"
  else
    cat <<EOF
[ERROR] PyGhidra dependencies are missing in the active venv.

Install them explicitly:
  source $VENV_PATH/bin/activate
  pip install -r $REQUIREMENTS_FILE

Or run:
  bash scripts/setup_ghidra_env.sh --install-py-deps
EOF
    exit 1
  fi
fi

cat <<EOF
[OK] Ghidra environment preflight passed.

Recommended exports for this shell/session:
  export JAVA_HOME=${JAVA_HOME:-$USER_JDK_HOME}
  export PATH="\$JAVA_HOME/bin:\$PATH"
  source $VENV_PATH/bin/activate
EOF
