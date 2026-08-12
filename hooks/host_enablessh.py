# host-side enablessh hook (exec'd into build.py's globals, replacing the
# default console/ssh enable path).
#
# Redox ships no ssh server and never will on 0.9.0, so there is nothing to
# "enable" -- the agent was already injected offline by host_prepareImage.py
# and init started it at boot. What this hook does instead is PROVE the agent
# is answering before the pipeline goes on to export the image, so a broken
# image fails here rather than at first use.
#
# History worth keeping: this hook used to end in sys.exit(3), a deliberate
# wall marking "Redox cannot be finalized". That verdict rested on two
# mistakes -- that a no_std binary could not spawn a process (the kernel has no
# spawn syscall, but spawning moved to userspace into the no_std, libc-
# independent redox-rt crate), and that injected binaries could not run at all
# (only relibc-linked ones cannot, and the agent links redox-rt instead). Both
# are now disproven by a working agent, so the wall is gone.

import socket
import sys
import time

_PORT = int(env("VM_SSH_PORT") or "2222")
_HOST = "127.0.0.1"

IAC, SE, SB, WILL, WONT, DO, DONT = 255, 240, 250, 251, 252, 253, 254


def _probe(port, cmds, settle=8.0, timeout=15):
    """Speak enough telnet to run a command and read the reply."""
    out = bytearray()
    sock = socket.create_connection((_HOST, port), timeout)
    sock.sendall(bytes([IAC, WILL, 0, IAC, DO, 0]))
    state = {"st": 0, "verb": 0}

    def eat(data):
        for b in data:
            if state["st"] == 0:
                if b == IAC:
                    state["st"] = 1
                else:
                    out.append(b)
            elif state["st"] == 1:
                if b == IAC:
                    out.append(IAC)
                    state["st"] = 0
                elif b == SB:
                    state["st"] = 3
                elif b in (WILL, WONT, DO, DONT):
                    state["verb"] = b
                    state["st"] = 2
                else:
                    state["st"] = 0
            elif state["st"] == 2:
                if state["verb"] == DO:
                    sock.sendall(bytes([IAC, WILL if b == 0 else WONT, b]))
                elif state["verb"] == WILL:
                    sock.sendall(bytes([IAC, DO if b == 0 else DONT, b]))
                state["st"] = 0
            else:
                if b == SE:
                    state["st"] = 0

    def rd(seconds):
        end = time.time() + seconds
        sock.settimeout(0.5)
        while time.time() < end:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                continue
            if not data:
                return
            eat(data)

    rd(2.0)
    for c in cmds:
        sock.sendall(c.encode("utf-8") + b"\r\n")
        rd(settle)
    sock.close()
    return out.decode("utf-8", "replace")


log("=" * 70)
log("enablessh: verifying the injected agent answers on %s:%d" % (_HOST, _PORT))

# The guest is still finishing boot when this runs; retry rather than
# demanding it be ready on the first try. A bare TCP connect is NOT a
# readiness signal -- QEMU's slirp binds the host side of a hostfwd the moment
# QEMU starts, so connect() succeeds long before anything listens in the
# guest. Only a marker that comes back proves the agent is alive.
_text = ""
_ok = False
for _attempt in range(30):
    try:
        # The same probe anyvm.py's telnet_ready() uses. ion collapses '' the
        # way rc and sh do, so the split marker reassembles -- and because the
        # agent never echoes the line it was sent, a matching echo cannot
        # produce a false positive.
        _text = _probe(_PORT, ["echo anyvm''-ready", "uname"])
        if "anyvm-ready" in _text:
            _ok = True
            break
    except OSError as _e:
        pass
    time.sleep(10)

if _ok:
    log("enablessh: agent is up. Transcript:")
    for _line in _text.splitlines():
        if _line.strip():
            log("    | %s" % _line.strip())
    log("=" * 70)
else:
    log("enablessh: the agent never answered the readiness marker.")
    log("           Last transcript: %r" % _text[-400:])
    log("=" * 70)
    # build.py has no fatal(); the convention across this tree is a FATAL log
    # line plus a non-zero exit, which aborts the hook and the build.
    log("FATAL: redox agent did not come up; refusing to export a broken image")
    sys.exit(1)
