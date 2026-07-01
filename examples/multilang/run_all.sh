#!/usr/bin/env bash
# Orchestrator: start eval-server, run Node / Ruby / Java / Rust tests, summarize.
set -euo pipefail

# Load secrets from .env if OPENAI_API_KEY not already set
if [[ -z "${OPENAI_API_KEY:-}" ]]; then
  ENV_FILE="$HOME/immunity-test-env/immunity-agent/.env"
  if [[ -f "$ENV_FILE" ]]; then
    set -a; source "$ENV_FILE"; set +a
  fi
fi

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
  echo "❌ OPENAI_API_KEY not set and .env not found"; exit 1
fi
export OPENAI_API_KEY

VENV_PYTHON="$HOME/immunity-test-env/immunity-agent/.venv/bin/python3"
WORKSPACE="$HOME/immunity-test-env/immunity-agent"
EVAL_PORT=7074
EVAL_URL="http://127.0.0.1:${EVAL_PORT}"
TEST_DIR="$HOME/immunity-test-env"

# ── start eval-server ─────────────────────────────────────────────────────────
echo "▶ Starting eval-server on port $EVAL_PORT…"
PYTHONPATH="$WORKSPACE" "$VENV_PYTHON" -m warden.eval_server --port "$EVAL_PORT" > /tmp/eval_server.log 2>&1 &
SERVER_PID=$!

cleanup() { kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; }
trap cleanup EXIT

sleep 2

# Confirm it's up
HEALTH=$(curl -sf "${EVAL_URL}/health" 2>/dev/null || echo "{}")
if ! echo "$HEALTH" | grep -q '"ok"'; then
  echo "❌ eval-server did not start. Log:"
  cat /tmp/eval_server.log
  exit 1
fi
echo "✅ eval-server up: $HEALTH"
echo ""

RESULTS=()

# ── Node.js ───────────────────────────────────────────────────────────────────
echo "══════════════════════════════════════════════"
echo " Language: Node.js v$(node --version)"
echo "══════════════════════════════════════════════"
if node "$TEST_DIR/node_openai_test.mjs"; then
  RESULTS+=("✅ Node.js")
else
  RESULTS+=("❌ Node.js")
fi
echo ""

# ── Ruby ──────────────────────────────────────────────────────────────────────
echo "══════════════════════════════════════════════"
echo " Language: $(ruby --version)"
echo "══════════════════════════════════════════════"
if ruby "$TEST_DIR/ruby_openai_test.rb"; then
  RESULTS+=("✅ Ruby")
else
  RESULTS+=("❌ Ruby")
fi
echo ""

# ── Java ──────────────────────────────────────────────────────────────────────
echo "══════════════════════════════════════════════"
echo " Language: $(java --version 2>&1 | head -1)"
echo "══════════════════════════════════════════════"
cd /tmp
mkdir -p /tmp/java_test_classes
if javac "$TEST_DIR/WardenOpenAITest.java" -d /tmp/java_test_classes 2>&1 && \
   java -cp /tmp/java_test_classes WardenOpenAITest; then
  RESULTS+=("✅ Java")
else
  RESULTS+=("❌ Java")
fi
echo ""

# ── Rust ─────────────────────────────────────────────────────────────────────
echo "══════════════════════════════════════════════"
echo " Language: $(rustc --version)"
echo "══════════════════════════════════════════════"
RUST_PROJ="$HOME/immunity-test-env/rust-warden-test"
mkdir -p "$RUST_PROJ/src"
cp "$TEST_DIR/rust_openai_test.rs" "$RUST_PROJ/src/main.rs"

cat > "$RUST_PROJ/Cargo.toml" <<'EOF'
[package]
name = "rust-warden-test"
version = "0.1.0"
edition = "2021"

[dependencies]
ureq = { version = "2", features = ["tls"] }
EOF

if (cd "$RUST_PROJ" && cargo build --release -q 2>&1 && "$RUST_PROJ/target/release/rust-warden-test"); then
  RESULTS+=("✅ Rust")
else
  RESULTS+=("❌ Rust")
fi
echo ""

# ── summary ───────────────────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Multi-language eval-server results                   ║"
echo "╠══════════════════════════════════════════════════════╣"
for r in "${RESULTS[@]}"; do
  printf "║  %-52s ║\n" "$r"
done
echo "╚══════════════════════════════════════════════════════╝"
