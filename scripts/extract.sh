#!/usr/bin/env bash

rm -rf dump
mkdir -p dump/calling_func_name

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
PROJECT_ROOT="$REPO_ROOT/GolangAnalyzerExtension"

PROJECT_LOCATION="${1:-}"
PROJECT_NAME="${2:-}"
TARGETS_DIR="${3:-}"

if [[ -z "$PROJECT_LOCATION" || -z "$PROJECT_NAME" || -z "$TARGETS_DIR" ]]; then
  echo "Usage: $0 <PROJECT_LOCATION> <PROJECT_NAME> <TARGETS_DIR>" >&2
  exit 1
fi

if [[ -z "${GHIDRA_INSTALL_DIR:-}" ]]; then
  echo "GHIDRA_INSTALL_DIR is not set." >&2
  exit 1
fi

if [[ ! -d "$TARGETS_DIR" ]]; then
  echo "TARGETS_DIR not found: $TARGETS_DIR" >&2
  exit 1
fi

while IFS= read -r -d '' target; do
  printf '%s\n' "$target"
  name=$(basename "$target")
  printf '%s\n' "$name"
  "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJECT_LOCATION" "$PROJECT_NAME" -import "$target" -scriptPath "$(pwd)" -postScript dump_calling_func.py
done < <(find "$TARGETS_DIR" -mindepth 1 -maxdepth 1 -print0)

python3 make_common_calling_func.py

RESOURCES_DIR="$PROJECT_ROOT/src/main/resources"
mkdir -p "$RESOURCES_DIR"
cp -a dump/. "$RESOURCES_DIR/"
