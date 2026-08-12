

| Release | x86_64 |
|---------|---------|
| 0.9.0 | ✅ (tar) |

> ℹ️ **Telnet + tar, not SSH.** Redox ships no remote-access server of any
> kind, so this builder bakes one in: the official prebuilt image is
> downloaded and `files/anyvmd.rs` -- a `#![no_std]` agent -- is
> offline-injected into it. anyvm drives that agent over telnet and syncs with
> `--sync tar`, the same shape as the plan9 and reactos builders. `/bin/tar`
> is already on the stock image, so unlike ReactOS nothing else has to be
> baked in.
>
> The agent links `redox-rt` rather than relibc, which is what makes it
> possible: the 0.9.0 kernel has no process-creation syscall at all -- no
> `clone`, `fexec`, `spawn` or `fork` -- because spawning moved into userspace
> into redox-rt, and redox-rt is itself `no_std` and libc-independent.
> See [NOTES.md](NOTES.md) and
> [files/anyvmd-design.md](files/anyvmd-design.md).
