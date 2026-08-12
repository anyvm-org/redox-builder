# host-side waitForLoginTag hook. Replaces the default "watch the serial
# console for VM_LOGIN_TAG" wait.
#
# NOT because the serial port is silent -- an earlier version of this comment
# claimed that, and a captured boot disproves it: build/redox.serial.log fills
# with the kernel log, the driver chatter, the DHCP transcript, and a
# "redox login:" prompt. Matching VM_LOGIN_TAG on serial would in fact work.
#
# The reason to replace it is that the login prompt is the wrong thing to wait
# for. It says a getty is up on the console; it says nothing about the agent,
# which is what the rest of the pipeline actually talks to. Waiting on a
# marker from the agent means a guest whose agent failed to start fails HERE,
# loudly, instead of being exported as a broken image.
#
# Two details that are easy to get wrong:
#
# 1. PROBE WITH A MARKER, NOT A BARE CONNECT. An earlier version of this hook
#    called a successful connect() "ready" and moved on -- and it "passed"
#    after 4 seconds with zero bytes received, on a guest that had not even
#    finished booting. QEMU's slirp binds the HOST side of a hostfwd the
#    moment QEMU starts and only reaches for the guest once data flows, so
#    connect() succeeding proves nothing whatsoever. Only a marker that comes
#    back proves the agent is alive.
#
# 2. THE ENTER TAPS ARE INSURANCE, NOT A KNOWN REQUIREMENT. Redox's bootloader
#    can stop on an interactive video-mode list, and nothing in build.py would
#    ever send a keypress. Whether THIS image + machine combination shows that
#    menu is not established: a captured boot reached the login prompt, and no
#    menu text appears anywhere in the serial log -- but the taps were being
#    sent during that boot, so it does not settle the question. They are kept
#    because they cost nothing when unnecessary: an Enter that lands on the
#    login prompt just reprints it (the captured framebuffer shows exactly
#    that, one "redox login:" per tap). `sendkey ret` through the QEMU monitor
#    is verified to reach the guest -- unlike RISC OS, where no keypress can.

import socket
import time

_PORT = int(env("VM_SSH_PORT") or "2222")
_HOST = "127.0.0.1"
_DEADLINE = 900          # 15 min: TCG boot plus the agent's own start-up
_IAC, _SE, _SB, _WILL, _WONT, _DO, _DONT = 255, 240, 250, 251, 252, 253, 254


def _marker_probe():
    """One telnet round trip. True only if the agent echoed the marker back."""
    out = bytearray()
    try:
        sock = socket.create_connection((_HOST, _PORT), 5)
    except OSError:
        return False
    try:
        sock.sendall(bytes([_IAC, _WILL, 0, _IAC, _DO, 0]))
        st = [0, 0]

        def eat(data):
            for b in data:
                if st[0] == 0:
                    if b == _IAC:
                        st[0] = 1
                    else:
                        out.append(b)
                elif st[0] == 1:
                    if b == _IAC:
                        out.append(_IAC)
                        st[0] = 0
                    elif b == _SB:
                        st[0] = 3
                    elif b in (_WILL, _WONT, _DO, _DONT):
                        st[1] = b
                        st[0] = 2
                    else:
                        st[0] = 0
                elif st[0] == 2:
                    if st[1] == _DO:
                        sock.sendall(bytes([_IAC, _WILL if b == 0 else _WONT, b]))
                    elif st[1] == _WILL:
                        sock.sendall(bytes([_IAC, _DO if b == 0 else _DONT, b]))
                    st[0] = 0
                else:
                    if b == _SE:
                        st[0] = 0

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

        rd(1.5)
        # ion collapses '' the way rc and sh do, and the agent never echoes
        # the line it was sent, so a matching echo cannot fake this.
        sock.sendall(b"echo anyvm''-ready\r\n")
        rd(6.0)
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return b"anyvm-ready" in bytes(out)


log("waitForLoginTag: waiting for anyvmd to answer the readiness marker on "
    "%s:%d (a login tag would only prove a getty is up), tapping Enter in "
    "case the bootloader is showing its video-mode menu" % (_HOST, _PORT))

_start = time.time()
_ok = False
_n = 0
while time.time() - _start < _DEADLINE:
    _n += 1
    # Keep tapping Enter for the first minute: the menu appears a few seconds
    # in, and the exact moment depends on how fast the host is.
    if _n <= 15:
        qmon("sendkey ret")
    if _marker_probe():
        _ok = True
        break
    if _n % 10 == 0:
        log("waitForLoginTag: still waiting, %ds elapsed" % int(time.time() - _start))
    time.sleep(4)

if _ok:
    log("waitForLoginTag: anyvmd answered the marker after %ds"
        % int(time.time() - _start))
else:
    log("waitForLoginTag: no marker after %ds -- the guest never reached a "
        "usable state" % _DEADLINE)
