#!/usr/bin/env bash
set -euo pipefail

# RAPIDSNARK BUILD: THE DOUBLE TAP
# 1. Force CMake to use NASM (not GNU ASM).
# 2. Force JS Generator to emit ADX/BMI2 (Unrolled Loops).

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${ROOT}/relayer/bin/rapidsnark"

if [[ "$(uname -s)" != "Linux" ]]; then echo "❌ Linux only."; exit 1; fi

WORK="${ROOT}/.rapidsnark-build-tmp"
rm -rf "${WORK}"
mkdir -p "${WORK}"

echo "==> [1/6] Installing dependencies..."
# We NEED nodejs for the generator and nasm for the compilation
SUDO=""
if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi
${SUDO} apt-get update -y
${SUDO} apt-get install -y --no-install-recommends \
  build-essential cmake git nasm yasm curl m4 file \
  libgmp-dev libsodium-dev nodejs npm

echo "==> [2/6] Cloning Rapidsnark..."
git clone --depth 1 https://github.com/iden3/rapidsnark.git "${WORK}/rapidsnark"
cd "${WORK}/rapidsnark"
git submodule update --init --recursive

echo "==> [3/6] APPLYING PATCHES..."

# PATCH 1: Fix the CMakeLists.txt you showed me
# We change "LANGUAGES CXX C ASM" to "LANGUAGES CXX C ASM_NASM"
echo "    → Switching CMake to use NASM..."
sed -i 's/LANGUAGES CXX C ASM/LANGUAGES CXX C ASM_NASM/g' CMakeLists.txt

# PATCH 2: The JS Injection (Force Unrolled Assembly)
# We find the generator script and inject code at the top to force the flags.
echo "    → Injecting speed flags into generate_asm.js..."
GEN_FILES=$(find . -name "generate_asm.js")
for file in $GEN_FILES; do
    # Insert code at line 1 to force ADX/BMI2 flags
    sed -i '1s/^/process.argv.push("-adx", "-bmi2");\n/' "$file"
    echo "       💉 Injected hack into $file"
done

# PATCH 3: Force C++ Compiler optimization flags for portability
find . -name "CMakeLists.txt" -print0 | xargs -0 sed -i 's/-march=native/-march=x86-64-v3 -madx -mbmi2/g'

echo "==> [4/6] Building Static GMP..."
./build_gmp.sh host

echo "==> [5/6] Compiling Prover..."
rm -rf build_prover && mkdir build_prover && cd build_prover

# Now we run CMake. It will see ASM_NASM and pick up our patched generator.
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_ASM_NASM_COMPILER="$(command -v nasm)" \
    -DCMAKE_CXX_FLAGS="-march=x86-64-v3 -madx -mbmi2 -O3" \
    -DENABLE_ASSEMBLY=ON

make -j"$(nproc)" prover

# Locate Binary
BIN=""
if [[ -f "prover" ]]; then BIN="prover";
elif [[ -f "src/prover" ]]; then BIN="src/prover";
else BIN=$(find . -type f -name prover -perm -u+x | head -n 1); fi

if [[ -z "${BIN}" ]]; then echo "❌ Build Failed: No binary found."; exit 1; fi

echo "==> [6/6] FINAL VERIFICATION"
file "${BIN}"
SIZE="$(stat -c%s "${BIN}")"
echo "   Size: ${SIZE} bytes"

# SIZE CHECK: 
# If this works, the size will be > 2,000,000 bytes.
if [[ "${SIZE}" -lt 2000000 ]]; then
  echo "❌ FAILURE: Binary is still small (${SIZE} bytes)."
  echo "   The build system is fighting back. Check if 'nasm' is installed."
  exit 1
fi

echo "SUCCESS: Fast Binary Created (~3MB)."
echo "==> Copying to ${OUT}"
cp -f "${BIN}" "${OUT}"
chmod +x "${OUT}"
echo "==> Done."