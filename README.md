

[![Build](https://github.com/anyvm-org/redox-builder/actions/workflows/build.yml/badge.svg)](https://github.com/anyvm-org/redox-builder/actions/workflows/build.yml)

Latest: 0.0.0


The image builder for `redox`


All the supported releases are here:


| Release | x86_64 (amd64) |
|---------|----------------|
|  0.9.0  |  ⚠️            |

> ⚠️ **Telnet, not SSH.** Redox ships no remote-access server of any kind, so
> this builder bakes one in: the official prebuilt image is downloaded and
> `files/anyvmd.rs` -- a `#![no_std]` agent -- is offline-injected into it.
> anyvm drives that agent over telnet and syncs with `--sync tar`. Same shape
> as the plan9 and reactos builders.
>
> The agent links [`redox-rt`](https://gitlab.redox-os.org/redox-os/relibc),
> not relibc, and that is what makes it possible: the 0.9.0 kernel has **no
> process-creation syscall at all** -- no `clone`, no `fexec`, no `spawn`, no
> `fork` -- because spawning moved into userspace, into redox-rt, which is
> itself `no_std` and libc-independent. So the agent gets real process creation
> while never linking the relibc CRT that faults on this frozen image.
>
> Two guest quirks it has to work around, both verified rather than assumed:
> a child needs a **pty**, because relibc resolves terminal queries by fd
> scheme and a program that asks about its terminal on a raw socket blocks
> forever; and Redox's `tar` is the old BSD form, so `tar x`, not `tar -xf -`.
> See [files/anyvmd-design.md](files/anyvmd-design.md).



How to build:

1. Use the [manual.yml](.github/workflows/manual.yml) to build manually.

    Run the workflow manually, you will get a view-only webconsole from the output of the workflow, just open the link in your web browser.

    You will also get an interactive VNC connection port from the output, you can connect to the vm by any vnc client.

2. Run the builder locally on your Ubuntu machine.

    Just clone the repo. and run:
    ```bash
    python3 build.py conf/redox-0.9.0.conf
    ```
