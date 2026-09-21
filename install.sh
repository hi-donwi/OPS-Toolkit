#!/usr/bin/env bash
#
# opskit installer.
#
#   curl -fsSL https://raw.githubusercontent.com/hi-donwi/OPS-Toolkit/main/install.sh | bash
#
# Environment overrides:
#   OPSKIT_VERSION   release tag to install, or "latest" (default)
#   INSTALL_DIR      destination directory (default: /usr/local/bin)
#   OPSKIT_SKIP_CHECKSUM=1   skip checksum verification (not recommended)

# -u catches unset variables; -o pipefail stops a failed download from being
# masked by a later successful pipe stage.
set -euo pipefail

REPO="hi-donwi/OPS-Toolkit"
BINARY_NAME="opskit"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${OPSKIT_VERSION:-latest}"

die() { echo "Error: $*" >&2; exit 1; }
info() { echo "$*"; }

echo "================================================="
echo "        opskit — OPS Toolkit Installer           "
echo "================================================="

# ---------------------------------------------------------------------------
# 1. Detect platform
# ---------------------------------------------------------------------------
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  linux)  OS_TARGET="linux" ;;
  darwin) OS_TARGET="darwin" ;;
  *)      die "unsupported operating system '$OS'" ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  ARCH_TARGET="amd64" ;;
  aarch64|arm64) ARCH_TARGET="arm64" ;;
  *)             die "unsupported architecture '$ARCH'" ;;
esac

TARGET_NAME="${BINARY_NAME}-${OS_TARGET}-${ARCH_TARGET}"
info "Detected platform: ${OS_TARGET}/${ARCH_TARGET}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# ---------------------------------------------------------------------------
# 2. Obtain the binary
#
# A locally built binary is only used when the caller did not ask for a specific
# release. Preferring ./bin over an explicit OPSKIT_VERSION would silently
# install something other than what was requested.
# ---------------------------------------------------------------------------
verify_checksum() {
  local file="$1" tag="$2" name="$3"

  if [ "${OPSKIT_SKIP_CHECKSUM:-0}" = "1" ]; then
    info "Skipping checksum verification (OPSKIT_SKIP_CHECKSUM=1)."
    return 0
  fi

  local sums="${TMP_DIR}/checksums.txt"
  if ! curl -fsSL "https://github.com/${REPO}/releases/download/${tag}/checksums.txt" -o "$sums"; then
    die "could not download checksums.txt for ${tag}. Refusing to install an unverified binary. Set OPSKIT_SKIP_CHECKSUM=1 to override."
  fi

  local expected
  expected="$(awk -v n="$name" '$2 == n || $2 == "*"n {print $1}' "$sums" | head -1)"
  [ -n "$expected" ] || die "no checksum recorded for ${name} in ${tag}."

  local actual
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  else
    die "neither sha256sum nor shasum is available to verify the download."
  fi

  [ "$actual" = "$expected" ] || die "checksum mismatch for ${name}. Expected ${expected}, got ${actual}. Not installing."
  info "Checksum verified."
}

SRC_BINARY=""

if [ "$VERSION" = "latest" ] && [ -f "./bin/${TARGET_NAME}" ]; then
  info "Using local build ./bin/${TARGET_NAME}"
  SRC_BINARY="./bin/${TARGET_NAME}"
elif [ "$VERSION" = "latest" ] && [ -f "./bin/${BINARY_NAME}" ]; then
  info "Using local build ./bin/${BINARY_NAME}"
  SRC_BINARY="./bin/${BINARY_NAME}"
else
  if [ "$VERSION" = "latest" ]; then
    RELEASE_TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -1 || true)"
  else
    RELEASE_TAG="$VERSION"
  fi

  if [ -n "${RELEASE_TAG:-}" ]; then
    info "Downloading ${BINARY_NAME} ${RELEASE_TAG} for ${OS_TARGET}/${ARCH_TARGET}..."
    SRC_BINARY="${TMP_DIR}/${BINARY_NAME}"

    if curl -fsSL "https://github.com/${REPO}/releases/download/${RELEASE_TAG}/${TARGET_NAME}" -o "$SRC_BINARY" 2>/dev/null; then
      verify_checksum "$SRC_BINARY" "$RELEASE_TAG" "$TARGET_NAME"
    else
      SRC_BINARY=""
      info "No published binary found for ${RELEASE_TAG}."

      # An explicit version request that cannot be satisfied is an error.
      # Quietly substituting a source build would install something other than
      # what the caller asked for.
      if [ "$VERSION" != "latest" ]; then
        die "release ${RELEASE_TAG} has no ${TARGET_NAME} asset. Check the tag, or unset OPSKIT_VERSION to build from source."
      fi
    fi
  fi

  # No release published yet: build from a source checkout if we are in one.
  if [ -z "$SRC_BINARY" ]; then
    [ -f "./go.mod" ] || die "no release binary available and this is not a source checkout."
    command -v go >/dev/null 2>&1 || die "no release binary available and Go is not installed to build from source."

    info "Building from source..."
    SRC_BINARY="${TMP_DIR}/${BINARY_NAME}"
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$SRC_BINARY" .
  fi
fi

chmod +x "$SRC_BINARY"

# ---------------------------------------------------------------------------
# 3. Install
# ---------------------------------------------------------------------------
DEST="${INSTALL_DIR}/${BINARY_NAME}"

if [ -w "$INSTALL_DIR" ]; then
  cp "$SRC_BINARY" "$DEST"
elif command -v sudo >/dev/null 2>&1; then
  info "Elevated permissions required to write to ${INSTALL_DIR}."
  sudo cp "$SRC_BINARY" "$DEST"
else
  die "${INSTALL_DIR} is not writable and sudo is unavailable. Set INSTALL_DIR to a writable path."
fi

info ""
info "Installed ${BINARY_NAME} to ${DEST}"
"$DEST" version || true
info ""
info "Next: 'opskit diag' to run diagnostics, or 'opskit --help' for all commands."
