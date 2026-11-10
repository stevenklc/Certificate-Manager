#!/usr/bin/env bash
# 在 Linux / WSL 交叉編譯 Windows 版（x86_64-pc-windows-gnullvm），不需要 Visual Studio。
#
# 事前準備（一次即可）：
#   1. 下載 llvm-mingw（https://github.com/mstorsjo/llvm-mingw/releases）解壓到 ~/.local/opt
#   2. rustup target add x86_64-pc-windows-gnullvm
#
# 用法：scripts/build-windows.sh [輸出目錄]（預設 dist/windows）
# 可用 LLVM_MINGW 環境變數指定工具鏈位置。
set -euo pipefail

TARGET=x86_64-pc-windows-gnullvm
LLVM_MINGW="${LLVM_MINGW:-$(ls -d "$HOME"/.local/opt/llvm-mingw-* 2>/dev/null | sort | tail -1)}"
if [[ -z "$LLVM_MINGW" || ! -x "$LLVM_MINGW/bin/x86_64-w64-mingw32-clang" ]]; then
    echo "找不到 llvm-mingw，請設定 LLVM_MINGW 或解壓到 ~/.local/opt" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist/windows}"
export PATH="$LLVM_MINGW/bin:$PATH"
export CC_x86_64_pc_windows_gnullvm=x86_64-w64-mingw32-clang
export AR_x86_64_pc_windows_gnullvm=llvm-ar
export CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER=x86_64-w64-mingw32-clang
# 靜態連結 libunwind / libc++ 等執行期程式庫，產出的 exe 不需要額外 DLL
export CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_RUSTFLAGS="-C target-feature=+crt-static"

cd "$ROOT"
cargo build --release --target "$TARGET" -p rustca-cli -p rustca-gui

TD="${CARGO_TARGET_DIR:-$ROOT/target}/$TARGET/release"
mkdir -p "$OUT"
cp "$TD/rust-ca.exe" "$TD/rust-ca-gui.exe" "$OUT/"
echo "完成：$OUT"
ls -la "$OUT"
