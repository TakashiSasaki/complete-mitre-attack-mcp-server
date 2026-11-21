#!/usr/bin/env bash
set -euo pipefail
export MCP_TRANSPORT=stdio
export MITRE_MCP_DATA_DIR=/data/complete-mitre-attack-mcp-server/data
exec /data/complete-mitre-attack-mcp-server/main/.venv/bin/mitre-mcp-server
