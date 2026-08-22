

[![Build](https://github.com/anyvm-org/redox-builder/actions/workflows/build.yml/badge.svg)](https://github.com/anyvm-org/redox-builder/actions/workflows/build.yml)

Latest: v2.0.1


The image builder for `redox`


All the supported releases are here:



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

How the images are built:

Each image is built automatically in the
[anyvm-org/redox-builder](https://github.com/anyvm-org/redox-builder)
repo's GitHub Actions: it downloads the official Redox OS harddrive
image, prepares it offline (console access and the anyvm runtime
support are injected into the image), verifies it by booting in QEMU,
and exports the disk as a compressed qcow2 image. No interactive
installer is run.

Upstream media: the official Redox OS release images from
https://static.redox-os.org/releases/ (project site:
https://www.redox-os.org/).




How to build:

1. Use the [manual.yml](.github/workflows/manual.yml) to build manually.
   
    Run the workflow manually, you will get a view-only webconsole from the output of the workflow, just open the link in your web browser.
   
    You will also get an interactive VNC connection port from the output, you can connect to the vm by any vnc client.

2. Run the builder locally on your Ubuntu machine.

    Just clone the repo. and run:
    ```bash
    python3 build.py conf/redox-0.9.0.conf
    ```
   
