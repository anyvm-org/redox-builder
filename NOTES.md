# redox-builder status notes

Durable technical status for this builder. (`README.md` is auto-regenerated
from `.github/tpl/README.tpl.md` by the readme workflow, so the detail lives
here instead.)

## TL;DR

Redox 0.9.0 (2024-09-07) is the only released Redox. It ships no
remote-access server of any kind, so this builder bakes one in: the official
prebuilt server image is downloaded, `files/anyvmd.rs` is built by
`tools/build-anyvmd.sh` and offline-injected with an init.d entry, and anyvm
drives it over **telnet** with **`--sync tar`**. Same shape as the plan9 and
reactos builders.

## The thing that makes it possible

The 0.9.0 kernel has **no process-creation syscall at all**. That is not an
inference -- the syscall dispatch table in the kernel at the release-day
commit (`9673fa26b6c0`, 2024-09-07) has no `CLONE`, no `FEXEC`, no `SPAWN`
and no `FORK`. Spawning moved entirely into userspace, into the `redox-rt`
crate, driven through `/scheme/thisproc/new/open_via_dup` and `dup()`
sub-handles.

`redox-rt` is itself `#![no_std]` and its Cargo.toml calls it a
"Libc-independent runtime" -- its only dependencies are bitflags, goblin,
plain, redox_syscall and generic-rt. **It does not depend on relibc.** So the
agent links redox-rt, gets real process creation, and never links the relibc
CRT (`relibc_start_v1`) that faults on this frozen image.

An earlier version of this document concluded the opposite -- that Redox was
"not anyvm-viable" -- on two mistakes worth recording, because both are easy
to make again:

1. *"Injected binaries cannot run."* Only **relibc-linked** ones cannot. A
   `no_std` binary with its own `_start`, linked `-nostartfiles`, runs fine.
2. *"The kernel returns ENOSYS for clone/fexec, so no_std cannot spawn."* The
   kernel really has no such syscall, but that is because spawning is a
   **userspace** job now -- and the crate that does it is one an agent can
   simply link.

## Two guest quirks the agent works around

Both were found by running it, not by reading.

**A child needs a pty, not the socket.** relibc dispatches fd queries on the
fd's *scheme* and understands only tcp, udp and chan
(`src/platform/redox/socket.rs:186-197`). Give a child a raw TCP socket as its
stdio and anything that asks about its terminal -- `ls` sizing its columns,
any shell -- goes down the tcp arm and waits forever for an answer smolnetd
never sends; `ps` shows it as `UB` (User Blocked) after ~0.01s of CPU. On a
pty the same binaries run normally. But a pty is a terminal and must not carry
a tar archive, so the agent uses **both**: `ion -c` on a pty for commands, and
the raw socket for tar, which is the one thing that never queries the
terminal.

Two hypotheses this killed on the way, both plausible and both wrong: it is
not the TLS segment (`/bin/diff` has byte-identical TLS to bash, 0xb8, and
works) and it is not shell-ness (`/bin/ls` is not a shell and hung).

**bash cannot be used at all.** It probes stdin with `getpeername()` to detect
being run from inetd, and relibc panics rather than returning ENOTSOCK:

```
RELIBC PANIC: socket.rs:194: socket Ok("/scheme/pty/18") doesn't match
either tcp, udp or chan schemes
```

No single fd is both a socket and a terminal, so there is no configuration
that satisfies it. `ion` is Redox's own shell, makes no such probe, and
handles `&&` and `;`.

**Redox's tar is the old BSD form.** `tar -xf -` is rejected outright
("unknown operation ... need to specify c[f] (create), t[f] (list), or x[f]
(extract)"). The `f` is optional, so the agent runs `tar x` (stdin) and
`tar c .`.

## Verified end to end

Against a stock image, driven exactly as anyvm.py drives it:

| leg | sent | got |
|---|---|---|
| readiness | `echo anyvm''-ready` | `anyvm-ready` |
| command | `echo A && uname; echo B` | `A` / `Redox` / `B` |
| tar push | the plan9 line + a real 10 KiB archive | `anyvm-tar-done` |
| verify | `ls /work; cat /work/justcheck.txt` | the file and its contents |

`ion` collapses `''` the way rc and sh do, so redox needs **no new arm** in
anyvm's `telnet_ready()` -- the existing generic probe works unchanged -- and
`&&`/`;` both work, so it uses the generic plan9 arm of `_tar_push_telnet`
rather than a riscos-style one where the agent parses the line itself.

## Build pinning, and why each pin matters

`tools/build-anyvmd.sh` pins three things, because "latest" is wrong in three
separate ways:

* **relibc at `3da3ff114e2251e41ef3342a9fbce6b6b40399d1`** (2024-09-07), so the
  userspace half of the spawn ABI matches the kernel inside the image.
* **`redox_syscall` at exactly `=0.5.3`.** The plain `"0.5.3"` in redox-rt's
  own Cargo.toml is a caret requirement that resolves to 0.5.18. 0.5.3 is the
  version that was current on the release date.
* **`nightly-2024-09-01`.** redox-rt gates on `asm_const`, `array_chunks`,
  `sync_unsafe_cell` and friends, and is `#![forbid(unreachable_patterns)]`,
  which a newer rustc can turn into an unsilenceable hard error.

Two build facts that cost time and are easy to re-break:

* Only three rustflags are needed, and the obvious lld set
  (`-C linker-flavor=ld.lld -C linker=rust-lld`) **fails** to link on this
  target, while `-C link-self-contained` is rejected outright. The default
  linker works.
* redox-rt cannot be built inside relibc's own tree: the workspace lists
  members that live in git submodules (`posix-regex`) and cargo resolves the
  whole workspace even for a crate that does not depend on them. Vendor
  `redox-rt`, `generic-rt` and `src/platform/auxv_defs.rs` -- the layout is
  forced by redox-rt's `#[path = "../../src/platform/auxv_defs.rs"]`.

## Injection traps

* `install -m 755` fails with EIO on this FUSE driver -- its chmod/utimes tail,
  not the copy. Use `tee` then `chmod`.
* `sudo` resets PATH, so `redoxfs` needs its full path.
* Do **not** pipe redoxfs' output: it daemonizes without closing stdout, so a
  `| tail` never sees EOF and hangs the build.
* FUSE refuses to mount over a non-empty directory, and a previous failed run
  that wrote into the bare mountpoint is exactly how that happens -- the write
  then "succeeds" against the host filesystem and every checksum agrees with
  itself. `host_prepareImage.py` checks for `/bin/ion` after mounting for that
  reason.
* The bootloader stops on an interactive video-mode menu. Under CI that needs
  a keypress; the guest is a normal x86 PC, so `sendkey ret` works.

## Still to do

* CI has never run: this repo has no release yet, and `anyvm.py` has no
  `redox` arm.
* `hooks/host_waitForLoginTag.py` probes the port; it could use the same
  marker probe `host_enablessh.py` does.
* The superseded `netshell/` prototype and `tools/build-netshell.sh` are still
  in the working tree but deliberately untracked.
