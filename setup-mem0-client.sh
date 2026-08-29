#!/usr/bin/env bash
#
# setup-mem0-client.sh
# Connect THIS Mac's Claude Code to the shared mem0 (OpenMemory) memory that
# runs on the always-on host "allenbots-mac-mini" over Tailscale.
#
# Run this ONCE on the client Mac (e.g. allens-mac-mini). It only needs Claude
# Code + Tailscale — no Docker/Ollama/9router (those live on the host).
#
# Usage:  bash setup-mem0-client.sh
#
set -euo pipefail

# --- config: the always-on mem0 host (this is the machine that ran the setup) ---
HOST_DNS="allenbots-mac-mini.tailf1cfae.ts.net"   # Tailscale MagicDNS name (stable)
HOST_TS_IP="100.73.41.41"                          # fallback tailnet IP
PORT="8765"
USER_ID="allen_bot"                                # shared brain: same user_id on both Macs
CLIENT_NAME="claude"                               # app label in the SSE path
SSE_PATH="/mcp/${CLIENT_NAME}/sse/${USER_ID}"
TOKEN_FILE="${OPENMEMORY_API_TOKEN_FILE:-$HOME/.config/openmemory/api-token}"

bold(){ printf "\033[1m%s\033[0m\n" "$1"; }
ok(){ printf "  \033[32m✓\033[0m %s\n" "$1"; }
warn(){ printf "  \033[33m!\033[0m %s\n" "$1"; }
die(){ printf "  \033[31m✗ %s\033[0m\n" "$1"; exit 1; }

bold "1) Checking Tailscale is up on this Mac…"
TS_BIN="$(command -v tailscale || echo /Applications/Tailscale.app/Contents/MacOS/Tailscale)"
[ -x "$TS_BIN" ] || die "Tailscale not found. Install it and sign in to the same account as the host."
"$TS_BIN" ip -4 >/dev/null 2>&1 || die "Tailscale not connected. Open the Tailscale app and sign in."
ok "Tailscale connected ($("$TS_BIN" ip -4 2>/dev/null | head -1))"

bold "2) Probing the mem0 host over Tailscale…"
TARGET=""
TOKEN="${OPENMEMORY_API_TOKEN:-}"
if [[ -z "$TOKEN" && -f "$TOKEN_FILE" ]]; then TOKEN="$(cat "$TOKEN_FILE")"; fi
[ -n "$TOKEN" ] || die "Set OPENMEMORY_API_TOKEN or provide $TOKEN_FILE before configuring the client."
for h in "$HOST_DNS" "$HOST_TS_IP"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 \
    -H "Authorization: Bearer ${TOKEN}" "http://${h}:${PORT}/healthz" 2>/dev/null || echo 000)
  if [ "$code" = "200" ]; then TARGET="$h"; ok "Reachable at http://${h}:${PORT} (HTTP 200)"; break; fi
  warn "No response from ${h}:${PORT} (got ${code})"
done
[ -n "$TARGET" ] || die "Cannot reach the mem0 host. Is allenbots-mac-mini awake and on the tailnet?"

URL="http://${TARGET}:${PORT}${SSE_PATH}"

bold "3) Registering the 'openmemory' MCP server (user scope)…"
# Remove any stale entry first so re-runs are clean (ignore errors if absent).
claude mcp remove --scope user openmemory >/dev/null 2>&1 || true
claude mcp add --transport sse --scope user openmemory "$URL" \
  --header "Authorization: Bearer ${TOKEN}"
ok "Registered: $URL"

bold "4) Writing the memory usage directive to ~/.claude/CLAUDE.md…"
CLAUDE_MD="$HOME/.claude/CLAUDE.md"
mkdir -p "$HOME/.claude"
MARK="## Memory: prefer mem0 (OpenMemory), neural-memory as backup"
if [ -f "$CLAUDE_MD" ] && grep -qF "$MARK" "$CLAUDE_MD" 2>/dev/null; then
  ok "Directive already present — left as-is."
else
  cat >> "$CLAUDE_MD" <<EOF

${MARK}

A shared self-hosted mem0 instance (OpenMemory) running on the host
"allenbots-mac-mini" over Tailscale is the **primary** cross-session memory,
exposed via the \`openmemory\` MCP server (tools: \`add_memories\`,
\`search_memory\`, \`list_memories\`, \`delete_*\`). It shares one brain with the
host Mac (same user_id \`${USER_ID}\`). \`neural-memory\` is the local backup.

- **Recall** with \`openmemory: search_memory\` before tasks that may depend on
  past context; fall back to neural-memory only if mem0 is unavailable.
- **Save** durable personal facts (identity, role, stable preferences, goals) with
  \`openmemory: add_memories\`. Pass natural sentences; mem0 extracts the facts.
- Project decisions and technical discoveries belong in AthenaBrain or project
  file-memory, not mem0. Don't double-write to both systems. Skip memory for one-off questions.
- This Mac is a CLIENT: it needs the host (allenbots-mac-mini) awake and on the
  tailnet. If \`openmemory\` tools error, the host or its stack is down.
EOF
  ok "Directive appended to $CLAUDE_MD"
fi

bold "5) Verifying connection…"
sleep 1
if claude mcp list 2>&1 | grep -qiE "openmemory.*Connected"; then
  ok "openmemory MCP server is Connected."
else
  warn "Not shown as Connected yet — this is normal; it loads on the NEXT Claude session."
fi

echo
bold "Done. Restart Claude Code on this Mac and it will share the host's mem0 memory."
echo "Dashboard is available on the host Mac at http://localhost:3000"
