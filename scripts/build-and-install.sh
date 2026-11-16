#!/bin/bash
# Builds OpenPGPMail with YOUR Apple signing identity and installs it to ~/Applications.
# Usage: DEVELOPMENT_TEAM=ABCDE12345 scripts/build-and-install.sh
set -euo pipefail
cd "$(dirname "$0")/.."

: "${DEVELOPMENT_TEAM:?Set DEVELOPMENT_TEAM to your Apple team ID (Xcode → Settings → Accounts → your team)}"
command -v xcodegen >/dev/null || { echo "xcodegen missing: brew install xcodegen" >&2; exit 1; }

DERIVED="$(mktemp -d)"
trap 'rm -rf "$DERIVED"' EXIT

xcodegen generate --quiet
xcodebuild -project OpenPGPMail.xcodeproj -scheme OpenPGPMailApp -configuration Release \
  -derivedDataPath "$DERIVED" -allowProvisioningUpdates \
  CODE_SIGN_STYLE=Automatic DEVELOPMENT_TEAM="$DEVELOPMENT_TEAM" build | grep -E "error|warning: |BUILD" || true

APP="$DERIVED/Build/Products/Release/OpenPGPMailApp.app"
[ -d "$APP" ] || { echo "Build failed." >&2; exit 1; }

mkdir -p "$HOME/Applications"
osascript -e 'quit app "OpenPGPMailApp"' >/dev/null 2>&1 || true
rm -rf "$HOME/Applications/OpenPGPMailApp.app"
cp -R "$APP" "$HOME/Applications/"
open "$HOME/Applications/OpenPGPMailApp.app"
echo "Installed to ~/Applications/OpenPGPMailApp.app – now enable the extension in Mail → Settings → Extensions and restart Mail."
