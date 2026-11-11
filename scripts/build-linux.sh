#!/usr/bin/env bash
# 編譯 Linux 版 CLI（含 TUI）為 musl 靜態執行檔：不依賴 glibc，
# 可直接複製到 Oracle Linux / RHEL 7、8、9 等舊版主機執行。
#
# 事前準備（一次即可）：
#   rustup target add x86_64-unknown-linux-musl
#   （C 編譯器使用系統的 gcc 即可，不需要 musl-gcc）
#
# 用法：scripts/build-linux.sh [輸出目錄]（預設 dist/linux）
set -euo pipefail

TARGET=x86_64-unknown-linux-musl
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist/linux}"
export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-gcc}"

cd "$ROOT"
cargo build --release --target "$TARGET" -p rustca-cli

TD="${CARGO_TARGET_DIR:-$ROOT/target}/$TARGET/release"
mkdir -p "$OUT"
cp "$TD/rust-ca" "$OUT/"
echo "完成：$OUT"
file "$OUT/rust-ca" 2>/dev/null || true
ls -la "$OUT"
