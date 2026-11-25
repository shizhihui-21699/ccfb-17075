#!/usr/bin/env bash
set -euo pipefail

# Convenience cross-build/test-compile script for macOS/Linux with MinGW-w64.
# On Windows, use: cmake -S . -B build && cmake --build build --config Release

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT}/build-mingw"

cmake -S "${ROOT}" -B "${BUILD_DIR}" \
  -DCMAKE_TOOLCHAIN_FILE="${ROOT}/cmake/mingw-w64-x86_64.cmake" \
  -DCMAKE_BUILD_TYPE=Release

cmake --build "${BUILD_DIR}" -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"

echo
echo "Built Windows executables in ${BUILD_DIR}:"
ls -lh "${BUILD_DIR}"/*.exe
