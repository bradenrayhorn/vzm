set -Eeuo pipefail

WORKSPACE="${VZM_BUILDER_WORKSPACE:-/run/vzm-builder}"
REQUEST="$WORKSPACE/request.json"
OUTPUT_DEFAULT="$WORKSPACE/output"
RESULT_LINK="$WORKSPACE/result"
STATUS="$WORKSPACE/status.json"
STATUS_TMP="$WORKSPACE/status.json.tmp"
LOG="$WORKSPACE/build.log"

mkdir -p "$WORKSPACE" "$OUTPUT_DEFAULT"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

write_status() {
  local exit_code="$1"
  local status="failure"
  if [ "$exit_code" -eq 0 ]; then
    status="success"
  fi

  jq -n \
    --arg status "$status" \
    --arg log "$LOG" \
    --arg endedAt "$(date -Iseconds)" \
    --argjson exitCode "$exit_code" \
    '{ schemaVersion: 1, status: $status, exitCode: $exitCode, endedAt: $endedAt, log: $log }' \
    > "$STATUS_TMP" || true
  mv "$STATUS_TMP" "$STATUS" || true
  sync || true
}

finish() {
  local exit_code=$?
  # The host treats status.json as the completion marker and may stop the VM
  # immediately after it appears. Flush copied outputs before publishing status.
  sync || true
  write_status "$exit_code"
  exit "$exit_code"
}
trap finish EXIT

echo "vzm builder agent starting"
echo "workspace: $WORKSPACE"

if [ ! -f "$REQUEST" ]; then
  echo "missing build request: $REQUEST" >&2
  exit 64
fi

SCHEMA_VERSION="$(jq -r '.schemaVersion // 1' "$REQUEST")"
SOURCE_DIR="$(jq -r '.sourceDir // "/run/vzm-builder/source"' "$REQUEST")"
OUTPUT_DIR="$(jq -r '.outputDir // "/run/vzm-builder/output"' "$REQUEST")"
ATTRIBUTE="$(jq -r '.attribute // "guest-bundle"' "$REQUEST")"
FLAKE_REF="$(jq -r '.flakeRef // empty' "$REQUEST")"

if [ "$SCHEMA_VERSION" != "1" ]; then
  echo "unsupported request schemaVersion: $SCHEMA_VERSION" >&2
  exit 64
fi

if [ -z "$FLAKE_REF" ]; then
  if [ -z "$ATTRIBUTE" ] || [ "$ATTRIBUTE" = "null" ]; then
    FLAKE_REF="$SOURCE_DIR"
  else
    FLAKE_REF="$SOURCE_DIR#$ATTRIBUTE"
  fi
fi

if [ ! -d "$SOURCE_DIR" ]; then
  echo "sourceDir does not exist or is not a directory: $SOURCE_DIR" >&2
  exit 66
fi

mkdir -p "$OUTPUT_DIR"
rm -rf "$RESULT_LINK"

export NIX_CONFIG="experimental-features = nix-command flakes
accept-flake-config = true"

echo "nix version: $(nix --version)"
echo "building: $FLAKE_REF"
nix build --show-trace --print-build-logs --out-link "$RESULT_LINK" "$FLAKE_REF"

for required in kernel initrd manifest.json rootfs.squashfs; do
  if [ ! -e "$RESULT_LINK/$required" ]; then
    echo "built result is missing required bundle file: $required" >&2
    exit 65
  fi
done

echo "copying bundle to $OUTPUT_DIR"
find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
for required in kernel initrd manifest.json rootfs.squashfs; do
  cp -L "$RESULT_LINK/$required" "$OUTPUT_DIR/$required"
done

echo "builder agent finished successfully"
