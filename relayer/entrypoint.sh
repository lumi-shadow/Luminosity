#!/bin/sh
set -eu

log() {
  echo "[relayer-entrypoint] $*" 1>&2
}

choose_tmpdir() {
  # Prefer /dev/shm if present; relayer already prefers it, but we can force it.
  if [ -d /dev/shm ] && [ -w /dev/shm ]; then
    echo "/dev/shm"
    return
  fi
  echo "/tmp"
}

bytes_free() {
  # Return bytes available in a way that is safe for POSIX shell integer comparisons.
  # We avoid awk doing scientific-notation formatting for large numbers (e.g. 8.5e+09),
  # because `test`/`[` only accept plain integers.
  free_k="$(df -kP "$1" 2>/dev/null | awk 'NR==2 {print $4}')"
  # If df fails or returns nothing, fall back to 0.
  [ -n "${free_k:-}" ] || { echo 0; return; }
  echo $((free_k * 1024))
}

copy_to_shm_or_fallback() {
  src="$1"
  dst="$2"
  var="$3"

  if [ ! -f "$src" ]; then
    log "missing $src; leaving $var as-is"
    return
  fi

  shm_dir=$(dirname "$dst")
  if [ ! -d "$shm_dir" ] || [ ! -w "$shm_dir" ]; then
    log "$shm_dir not writable; using on-disk zkey for $var=$src"
    export "$var=$src"
    return
  fi

  need=$(wc -c <"$src" | tr -d ' ')
  free=$(bytes_free "$shm_dir" || echo 0)
  # Require a bit of headroom to avoid filling shm to 100%.
  headroom=$((need + need / 10))
  if [ "$free" -lt "$headroom" ]; then
    log "not enough free space in $shm_dir for $(basename "$src") (need~${headroom}B free=${free}B); using on-disk zkey for $var=$src"
    export "$var=$src"
    return
  fi

  # Copy if missing or size mismatch.
  if [ -f "$dst" ]; then
    cur=$(wc -c <"$dst" | tr -d ' ')
  else
    cur=0
  fi
  if [ "$cur" -ne "$need" ]; then
    log "copying $(basename "$src") -> $dst (size=${need}B)"
    cp -f "$src" "$dst"
  else
    log "zkey already present in shm: $dst"
  fi

  export "$var=$dst"
}

TMPDIR="$(choose_tmpdir)"
export RELAYER_TMPDIR="${RELAYER_TMPDIR:-$TMPDIR}"

# Default locations in the image
DEFAULT_WITHDRAW_SRC="/circuits/withdraw_final.zkey"
DEFAULT_WITHDRAW_LIQ_SRC="/circuits/withdraw_liquidity_final.zkey"
DEFAULT_DEPOSIT_ASSET_SRC="/circuits/deposit_asset_bind_final.zkey"
DEFAULT_DEPOSIT_LIQ_SRC="/circuits/deposit_liquidity_bind_final.zkey"
DEFAULT_SWAP_ZK_SRC="/circuits/swap_zk_final.zkey"

# Backwards-compatible behavior:
# - historically users set WITHDRAW_ZKEY_PATH=/dev/shm/... and manually copied.
# - now the entrypoint does the copy, so we treat those envs as *hints* but always fall back to /circuits.
resolve_src() {
  cand="$1"; fallback="$2"; label="$3"
  if [ ! -f "$cand" ] && [ -f "$fallback" ]; then
    log "$label source missing at '$cand'; falling back to '$fallback'"
    echo "$fallback"
  else
    echo "$cand"
  fi
}

WITHDRAW_SRC=$(resolve_src \
  "${WITHDRAW_ZKEY_SRC:-${WITHDRAW_ZKEY_PATH:-$DEFAULT_WITHDRAW_SRC}}" \
  "$DEFAULT_WITHDRAW_SRC" "WITHDRAW")
WITHDRAW_LIQ_SRC=$(resolve_src \
  "${WITHDRAW_LIQUIDITY_ZKEY_SRC:-${WITHDRAW_LIQUIDITY_ZKEY_PATH:-$DEFAULT_WITHDRAW_LIQ_SRC}}" \
  "$DEFAULT_WITHDRAW_LIQ_SRC" "WITHDRAW_LIQUIDITY")
DEPOSIT_ASSET_SRC=$(resolve_src \
  "${DEPOSIT_ASSET_BIND_ZKEY_SRC:-${DEPOSIT_ASSET_BIND_ZKEY_PATH:-$DEFAULT_DEPOSIT_ASSET_SRC}}" \
  "$DEFAULT_DEPOSIT_ASSET_SRC" "DEPOSIT_ASSET_BIND")
DEPOSIT_LIQ_SRC=$(resolve_src \
  "${DEPOSIT_LIQUIDITY_BIND_ZKEY_SRC:-${DEPOSIT_LIQUIDITY_BIND_ZKEY_PATH:-$DEFAULT_DEPOSIT_LIQ_SRC}}" \
  "$DEFAULT_DEPOSIT_LIQ_SRC" "DEPOSIT_LIQUIDITY_BIND")
SWAP_ZK_SRC=$(resolve_src \
  "${SWAP_ZK_ZKEY_SRC:-${SWAP_ZK_ZKEY_PATH:-$DEFAULT_SWAP_ZK_SRC}}" \
  "$DEFAULT_SWAP_ZK_SRC" "SWAP_ZK")

copy_to_shm_or_fallback "$WITHDRAW_SRC"      "$TMPDIR/withdraw_final.zkey"              "WITHDRAW_ZKEY_PATH"
copy_to_shm_or_fallback "$WITHDRAW_LIQ_SRC"  "$TMPDIR/withdraw_liquidity_final.zkey"    "WITHDRAW_LIQUIDITY_ZKEY_PATH"
copy_to_shm_or_fallback "$DEPOSIT_ASSET_SRC" "$TMPDIR/deposit_asset_bind_final.zkey"    "DEPOSIT_ASSET_BIND_ZKEY_PATH"
copy_to_shm_or_fallback "$DEPOSIT_LIQ_SRC"   "$TMPDIR/deposit_liquidity_bind_final.zkey" "DEPOSIT_LIQUIDITY_BIND_ZKEY_PATH"
copy_to_shm_or_fallback "$SWAP_ZK_SRC"       "$TMPDIR/swap_zk_final.zkey"               "SWAP_ZK_ZKEY_PATH"

log "RELAYER_TMPDIR=$RELAYER_TMPDIR"
log "WITHDRAW_ZKEY_PATH=$WITHDRAW_ZKEY_PATH"
log "WITHDRAW_LIQUIDITY_ZKEY_PATH=$WITHDRAW_LIQUIDITY_ZKEY_PATH"
log "DEPOSIT_ASSET_BIND_ZKEY_PATH=$DEPOSIT_ASSET_BIND_ZKEY_PATH"
log "DEPOSIT_LIQUIDITY_BIND_ZKEY_PATH=$DEPOSIT_LIQUIDITY_BIND_ZKEY_PATH"
log "SWAP_ZK_ZKEY_PATH=$SWAP_ZK_ZKEY_PATH"

exec /usr/local/bin/relayer


