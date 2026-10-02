#!/bin/sh
# Runs on the host: build the permissions editor and put it in the share of
# the VM that ../gxwi/dev/boot.sh started, with its icon for the base theme
# and its declaration for the catalogue. GXWI's dev service puts them where a
# package would, and its dev loop restarts on a new one.
#
# The rename makes the new binary appear whole, never half-written.
set -eu
cd "$(dirname "$0")/.."
. dev/env.sh
share=../gxwi/target/vmshare
[ -d "$share" ] || { echo "no $share: boot the VM from ../gxwi first" >&2; exit 1; }
cargo build --release
mkdir -p "$share/icons/base"
cp gxwi-sd-editor.svg "$share/icons/base/dev.peios.gxwi-sd-editor.svg"
mkdir -p "$share/apps"
cp dev.peios.gxwi-sd-editor.toml "$share/apps/dev.peios.gxwi-sd-editor.toml"
cp target/release/gxwi-sd-editor "$share/gxwi-sd-editor.new"
mv "$share/gxwi-sd-editor.new" "$share/gxwi-sd-editor"
