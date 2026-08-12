# redox anyvmd -- design, settled by the spike

Everything below is verified on the stock Redox 0.9.0 server image, not assumed.

## The mechanism

The 0.9.0 kernel has NO process-creation syscall (verified against the release
day kernel commit 9673fa26b6c0). Spawning lives in userspace in `redox-rt`,
which is `#![no_std]` and libc-independent, so the agent links it directly and
never touches the relibc CRT that UD2s on this frozen kernel.

Per child, in this exact order (each step is kernel-enforced):

1. point fd 0/1/2 at the pty slave  -- must be BEFORE the snapshot
2. `dup(cur_filetable, b"copy")`    -- the child's table can only be a copy of ours
3. `new_child_process()`            -- a fresh child already owns an addrspace
4. `dup(child, b"open_via_dup")`    -- a SECOND handle; fexec_impl consumes the one it is given
5. `fexec_impl(...)` with args and envs REVERSED
6. drop the addrspace handle        -- installs on close(), not on write()
7. write the filetable copy to `current-filetable`, then drop the selector
8. write `start`
9. `waitpid` with WNOHANG, pumping the pty on every turn

`argc + envc` must be ODD or the child's initial sp is not 16-aligned and it
dies on its first movaps with no message. The agent pads the environment
itself rather than leaving that as a caller rule.

## Why a pty, and not the socket

relibc dispatches fd queries on the fd's SCHEME and understands only tcp, udp
and chan (`src/platform/redox/socket.rs:186-197`). Give a child a raw TCP
socket as its stdio and:

* anything that asks about its terminal (`ls` sizing columns, any shell)
  goes down the tcp arm and waits forever for an answer smolnetd never sends
  -- `ps` shows it as `UB`, User Blocked, after ~0.01s of CPU;
* `bash` panics outright, because it probes stdin with `getpeername()` to
  detect being run from inetd.

Measured, same binary, only the stdio changed:

| binary | raw socket | pty |
|---|---|---|
| `uname`, `tar`, `diff --version`, `ps` | works | works |
| `ls /bin` | hangs (UB) | works, 2794 bytes |
| `ion -c "echo X; uname"` | hangs (UB) | **works, status 0** |
| `bash -c "exit 7"` | hangs (UB) | relibc panic, socket.rs:194 |

Two hypotheses this killed on the way: it is NOT the TLS segment (`diff` has
byte-identical TLS to bash, 0xb8, and works) and it is NOT shell-ness (`ls`
is not a shell and hung).

pty setup is relibc's own `openpty` (`src/header/pty/redox.rs`): open
`/scheme/pty` for the master, `fpath()` it to learn the slave path, open that.
ptyd is already running on the stock image.

## What this buys

redox gets a REAL shell, so it takes the generic plan9-style arm of
`_tar_push_telnet` (`... && tar x && echo marker`) unchanged -- ion collapses
`''` the way rc and sh do, so no new arm is needed. `/bin/tar` is on the stock
image, so nothing has to be baked in.

The tar LINES are still parsed by the agent rather than run by ion, the same
as riscos and reactos: the archive has to be unescaped on the way in and
escaped on the way out, and a shell cannot do that. That is also why anyvm's
`_tar_pull_telnet` gives redox `skip_echo=False` -- the agent never echoes the
line it was sent, so there is nothing to skip, and the plan9 default would eat
the first block of the archive instead.

bash is unusable regardless of what the agent does -- no single fd can be both
a socket and a terminal, and bash insists on asking whether stdin is a socket.
ion is Redox's own shell and does not.

## Open, for the agent itself

* which tar spelling Redox's tar wants for stdin (`tar x` vs `tar -xf -`)
* IAC escaping has to be applied on the way out and undone on the way in, and
  the tar stream is binary, so BINARY (RFC 856) must be negotiated both ways
