#!/bin/bash
# Build files/anyvmd.rs -- the Redox agent -- into files/anyvmd.bin.
#
# The agent is #![no_std] and links `redox-rt` rather than relibc. That is not
# a stylistic choice: the Redox 0.9.0 kernel has NO process-creation syscall
# (checked against the release-day kernel commit 9673fa26b6c0 -- its syscall
# dispatch table has no CLONE, no FEXEC, no SPAWN, no FORK), spawning lives in
# userspace in redox-rt, and redox-rt is itself no_std and libc-independent.
# Linking it gives real process creation while never pulling in the relibc CRT
# (relibc_start_v1), which executes UD2 on this frozen image.
#
# Everything here is pinned, because "latest" is wrong in three separate ways:
#   * relibc at the commit contemporaneous with the 0.9.0 release, so the
#     userspace half of the spawn ABI matches the kernel in the image;
#   * redox_syscall at EXACTLY 0.5.3 -- the plain "0.5.3" in redox-rt's own
#     Cargo.toml is a caret requirement that resolves to 0.5.18;
#   * a nightly from the same era, because redox-rt gates on asm_const,
#     array_chunks, sync_unsafe_cell and friends, and it is #![forbid(
#     unreachable_patterns)], which a newer rustc can turn into a hard error.
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$HERE")"
WORK="${1:-$REPO/build/anyvmd}"

RELIBC_COMMIT=3da3ff114e2251e41ef3342a9fbce6b6b40399d1   # 2024-09-07, Redox 0.9.0
NIGHTLY=nightly-2024-09-01
TARGET=x86_64-unknown-redox

mkdir -p "$WORK"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export PATH="$CARGO_HOME/bin:$PATH"

echo "--- toolchain ---"
if ! command -v rustup > /dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain none --profile minimal --no-modify-path
  . "$CARGO_HOME/env"
fi
rustup toolchain list | grep -q "$NIGHTLY" || \
  rustup toolchain install "$NIGHTLY" --profile minimal --component rust-src
rustup run "$NIGHTLY" rustc --print target-list | grep -qx "$TARGET" || {
  echo "FATAL: $TARGET is unknown to $NIGHTLY"; exit 1; }

echo "--- relibc @ $RELIBC_COMMIT ---"
REL="$WORK/relibc"
if [ ! -d "$REL/.git" ]; then
  git clone --filter=blob:none --no-checkout \
    https://github.com/redox-os/relibc.git "$REL"
fi
git -C "$REL" fetch --filter=blob:none origin "$RELIBC_COMMIT" 2>/dev/null \
  || git -C "$REL" fetch --filter=blob:none origin
git -C "$REL" -c advice.detachedHead=false checkout --force "$RELIBC_COMMIT"

# Vendor only the three directories redox-rt needs. Building inside relibc's
# own tree does not work: its workspace lists members that live in git
# submodules (posix-regex), and cargo resolves the whole workspace even when
# the crate being built does not depend on them.
#
# The layout is forced by redox-rt/src/lib.rs, which reaches back out of the
# crate with #[path = "../../src/platform/auxv_defs.rs"] -- hence the
# src/platform directory hanging off the vendored root.
#
# Vendor STRAIGHT into the crate's vendor-relibc: an intermediate staging copy
# would have to be cleaned between runs, and nothing here is worth a recursive
# delete. `cp -a <src>/. <dst>/` overwrites in place, so a re-run is idempotent
# without removing anything (RELIBC_COMMIT is pinned, so no file can go stale
# in a way that matters).
CR="$WORK/crates"
VEN="$CR/anyvmd/vendor-relibc"
mkdir -p "$VEN/redox-rt" "$VEN/generic-rt" "$VEN/src/platform"
cp -a "$REL/redox-rt/."   "$VEN/redox-rt/"
cp -a "$REL/generic-rt/." "$VEN/generic-rt/"
cp -a "$REL/src/platform/auxv_defs.rs" "$VEN/src/platform/auxv_defs.rs"
sed -i 's/^redox_syscall = "0\.5\.3"$/redox_syscall = "=0.5.3"/' \
  "$VEN/redox-rt/Cargo.toml"

echo "--- crate ---"
mkdir -p "$CR/anyvmd/src" "$CR/anyvmd/.cargo"
cp -a "$REPO/files/anyvmd.rs" "$CR/anyvmd/src/main.rs"

cat > "$CR/anyvmd/Cargo.toml" <<EOF
[package]
name    = "anyvmd"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "anyvmd"
path = "src/main.rs"

[dependencies]
redox-rt      = { path = "vendor-relibc/redox-rt" }
redox_syscall = "=0.5.3"

[profile.release]
panic     = "abort"
opt-level = "s"
EOF

# panic=abort is not optional: a no_std binary with panic=unwind needs an
# eh_personality lang item. compiler-builtins-mem supplies memcpy/memset/
# memmove/memcmp, which must NOT also be hand-written (duplicate symbols).
#
# Only three rustflags. The obvious lld set (-C linker-flavor=ld.lld
# -C linker=rust-lld) FAILS to link on this target, and -C link-self-contained
# is rejected outright ("not supported on this target"); the default linker
# works. Do not "improve" this list without rebuilding.
cat > "$CR/anyvmd/.cargo/config.toml" <<EOF
[build]
target = "$TARGET"

[unstable]
build-std          = ["core", "alloc", "compiler_builtins"]
build-std-features = ["compiler-builtins-mem"]

[target.$TARGET]
rustflags = [
  "-C", "relocation-model=static",
  "-C", "link-arg=-nostartfiles",
  "-C", "link-arg=-static",
]
EOF

echo "--- build ---"
( cd "$CR/anyvmd" && cargo "+$NIGHTLY" build --release )

OUT="$CR/anyvmd/target/$TARGET/release/anyvmd"
[ -f "$OUT" ] || { echo "FATAL: $OUT was not produced"; exit 1; }
cp -f "$OUT" "$REPO/files/anyvmd.bin"
strip "$REPO/files/anyvmd.bin" 2>/dev/null || true

# A dynamic binary would need a second fexec pass the agent does not implement,
# and the loader rejects overlapping PT_LOAD pages, so check both here rather
# than discovering it as a silent no-op inside the VM.
if readelf -lW "$REPO/files/anyvmd.bin" | grep -q INTERP; then
  echo "FATAL: anyvmd came out dynamic (PT_INTERP present)"; exit 1
fi
echo "--- done: $(stat -c%s "$REPO/files/anyvmd.bin") bytes ---"
readelf -hW "$REPO/files/anyvmd.bin" | grep -E 'Type:|Entry'
