# host-side prepareImage hook (exec'd into build.py's globals after
# _prep_vhd_disk materialized redox.img + redox.qcow2, but BEFORE the VM boots).
#
# Offline-inject the no_std anyvmd agent into the stock Redox 0.9.0 image:
#   1. ensure we have the raw redox.img (decompressed by _prep_vhd_disk),
#   2. expose its GPT partitions with `losetup -P` and pick the RedoxFS
#      partition (the largest one) -- mounting the partition device directly
#      means we never have to hardcode a sector offset,
#   3. mount it with the redoxfs FUSE driver pinned to 0.6.6 (the on-disk
#      format that ships in 0.9.0),
#   4. install anyvmd to /usr/bin/anyvmd and add /usr/lib/init.d/99_anyvmd
#      so init starts it at boot,
#   5. unmount, detach the loop device, and re-convert the modified raw image
#      back to redox.qcow2 (the disk build.py boots).
#
# Runs on a Linux host (GitHub Actions ubuntu runner / WSL / codespace). Needs
# sudo, qemu-img, cargo, and FUSE. This hook is the ONLY Redox-specific image
# surgery; everything else is the shared build.py pipeline.

import glob
import os
import subprocess
import time

_OSNAME = env("VM_OS_NAME") or "redox"
# EVERY build-generated path must go through build.py's own wf() (WORKDIR =
# "build"), because that is where _prep_vhd_disk writes the raw img + qcow2 and
# where the qemu launch reads the disk from. Bare relative names inject into a
# file in the repo root that nothing ever boots -- and the failure is silent:
# the build comes up on a pristine image and simply times out waiting for an
# agent that was written somewhere else entirely.
#
# (This hook briefly used bare names on the theory that wf() did not exist. It
# does; what did not exist was this repo's build.py -- it was a stale June-10
# copy predating both wf() and VM_TRANSPORT. Replacing it from base-builder
# restored the helper and turned the workaround into the bug.)
#
# Inputs (files/, tools/) are NOT routed through wf(): they live at the repo
# root and are read from there. See build.py's WORKDIR comment.
_RAW = wf("%s.img" % _OSNAME)
_QCOW = wf("%s.qcow2" % _OSNAME)
_MNT = os.path.abspath(wf("%s.redoxfs.mnt" % _OSNAME))
# A host_*.py hook is exec()'d INTO build.py's own globals, so `__file__` here
# is build.py -- NOT this file. dirname() is therefore already the repo root,
# and the "hooks/.." step a reader expects would climb one level too far,
# outside the checkout entirely. (The .sh hooks are real subprocesses and do
# compute HERE/.. correctly; only the .py ones have this trap.)
_REPO = os.path.dirname(os.path.abspath(__file__))
_AGENT_BIN = os.path.join(_REPO, "files", "anyvmd.bin")
_BUILD_SH = os.path.join(_REPO, "tools", "build-anyvmd.sh")
_REDOXFS_VERSION = "0.6.6"


def _run(cmd, **kw):
    log("prepareImage: $ %s" % " ".join(cmd))
    return subprocess.run(cmd, **kw)


def _run_ok(cmd, **kw):
    p = _run(cmd, **kw)
    if p.returncode != 0:
        raise RuntimeError("command failed (%d): %s" % (p.returncode, " ".join(cmd)))
    return p


def _ensure_raw():
    """Guarantee redox.img (raw) exists; derive it from the qcow2 if needed."""
    if os.path.exists(_RAW):
        return
    if os.path.exists(_QCOW):
        log("prepareImage: redox.img missing; converting from redox.qcow2")
        _run_ok(["qemu-img", "convert", "-f", "qcow2", "-O", "raw", _QCOW, _RAW])
        return
    raise RuntimeError("neither %s nor %s exists; _prep_vhd_disk did not run?"
                       % (_RAW, _QCOW))


def _ensure_agent():
    """Return a path to the anyvmd binary, building it if not committed."""
    if os.path.exists(_AGENT_BIN):
        log("prepareImage: using committed agent binary %s" % _AGENT_BIN)
        return _AGENT_BIN
    log("prepareImage: anyvmd.bin not found; building via %s" % _BUILD_SH)
    _run_ok(["bash", _BUILD_SH])
    if not os.path.exists(_AGENT_BIN):
        raise RuntimeError("build-anyvmd.sh did not produce %s" % _AGENT_BIN)
    return _AGENT_BIN


def _ensure_tools():
    """Install FUSE + the redoxfs driver (pinned to the 0.9.0 on-disk format)."""
    if subprocess.run(["which", "redoxfs"], capture_output=True).returncode != 0:
        # FUSE userspace + headers for the `fuser` crate redoxfs links against.
        _run(["sudo", "apt-get", "update"])
        _run(["sudo", "apt-get", "install", "-y",
              "fuse3", "libfuse3-dev", "libfuse-dev", "pkg-config"])
        log("prepareImage: installing redoxfs %s" % _REDOXFS_VERSION)
        _run_ok(["cargo", "install", "redoxfs", "--version", _REDOXFS_VERSION,
                 "--locked"])
    # cargo's bin dir may not be on PATH for subsequent calls.
    cbin = os.path.expanduser("~/.cargo/bin")
    if cbin not in os.environ.get("PATH", ""):
        os.environ["PATH"] = cbin + os.pathsep + os.environ.get("PATH", "")


def _bytes_size(dev):
    p = subprocess.run(["sudo", "blockdev", "--getsize64", dev],
                       capture_output=True, text=True)
    try:
        return int(p.stdout.strip())
    except ValueError:
        return 0


def _attach_loop():
    """losetup -P the raw image and return (loopdev, redoxfs_partition_dev)."""
    p = _run_ok(["sudo", "losetup", "-P", "-f", "--show", _RAW],
                capture_output=True, text=True)
    loopdev = p.stdout.strip()
    if not loopdev:
        raise RuntimeError("losetup returned no device")
    # Give the kernel a moment to create the partition nodes.
    time.sleep(1)
    parts = sorted(glob.glob(loopdev + "p*"))
    log("prepareImage: %s partitions: %s" % (loopdev, parts or "(none)"))
    if not parts:
        # No partition nodes -> the image may be a bare filesystem; fall back
        # to the whole device.
        return loopdev, loopdev
    # The RedoxFS data partition is the largest one.
    best = max(parts, key=_bytes_size)
    log("prepareImage: RedoxFS partition = %s (%d bytes)" % (best, _bytes_size(best)))
    return loopdev, best


def _inject(part_dev, agent_bin):
    os.makedirs(_MNT, exist_ok=True)
    # FUSE refuses to mount over a non-empty directory, and a previous failed
    # run that wrote into the bare mountpoint is exactly how that happens --
    # the write then "succeeds" against the host filesystem and every checksum
    # agrees with itself. Refuse rather than produce a convincing lie.
    if os.path.isdir(_MNT) and os.listdir(_MNT):
        raise RuntimeError("%s is not empty; a previous run wrote into an "
                           "unmounted mountpoint" % _MNT)
    # sudo resets PATH, so cargo's bin dir is not searched: give redoxfs its
    # full path. redoxfs mounts and daemonizes; the mountpoint ends up
    # root-owned. Do NOT pipe its output -- it keeps stdout open after
    # daemonizing, so a `| tail` never sees EOF and hangs the build.
    redoxfs = os.path.join(os.path.expanduser("~"), ".cargo", "bin", "redoxfs")
    if not os.path.exists(redoxfs):
        redoxfs = "redoxfs"
    _run_ok(["sudo", redoxfs, part_dev, _MNT])
    time.sleep(3)
    try:
        # Prove the mount is real before writing anything into it.
        #
        # This MUST go through sudo. redoxfs is mounted as root and FUSE does
        # not set allow_other by default, so the mounted tree is invisible to
        # everyone else -- an unprivileged os.path.exists() here reports "no
        # /bin/ion" on a perfectly good mount, which is exactly the false
        # alarm this check produced the first time it ran.
        if subprocess.run(["sudo", "test", "-e",
                           os.path.join(_MNT, "bin", "ion")]).returncode != 0:
            raise RuntimeError("%s does not look like the Redox filesystem "
                               "(no /bin/ion); did redoxfs actually mount?" % _MNT)
        _run(["sudo", "mkdir", "-p", os.path.join(_MNT, "usr", "bin")])
        _run(["sudo", "mkdir", "-p", os.path.join(_MNT, "usr", "lib", "init.d")])
        # `install` is NOT usable here: its chmod/utimes tail returns EIO on
        # this FUSE driver even though the copy itself worked. tee + chmod.
        agent_dst = os.path.join(_MNT, "usr", "bin", "anyvmd")
        with open(agent_bin, "rb") as fh:
            _run_ok(["sudo", "tee", agent_dst], stdin=fh, stdout=subprocess.DEVNULL)
        _run_ok(["sudo", "chmod", "755", agent_dst])
        # init.d entries are exec'd directly (not via a shell), one binary per
        # line, resolved on init's exec path. 99_ so it runs last: the agent
        # blocks in accept() and never returns.
        initd = os.path.join(_MNT, "usr", "lib", "init.d", "99_anyvmd")
        _run_ok(["sudo", "tee", initd], input=b"anyvmd\n",
                stdout=subprocess.DEVNULL)
        _run(["sudo", "ls", "-la", agent_dst])
        _run(["sudo", "sync"])
    finally:
        # Unmount even if a step above failed, so the loop device can detach.
        for umount in (["sudo", "fusermount3", "-u", _MNT],
                       ["sudo", "fusermount", "-u", _MNT],
                       ["sudo", "umount", _MNT]):
            if subprocess.run(umount, capture_output=True).returncode == 0:
                break
        time.sleep(1)


def _reconvert():
    """Rebuild redox.qcow2 from the now-injected raw image."""
    _run_ok(["qemu-img", "convert", "-f", "raw", "-O", "qcow2",
             "-o", "preallocation=off", _RAW, _QCOW])
    subprocess.run(["chmod", "0666", _QCOW])
    log("prepareImage: re-converted %s -> %s" % (_RAW, _QCOW))
    _run(["ls", "-lh", _QCOW])


# ---- hook body --------------------------------------------------------------

log("prepareImage: injecting anyvmd into the Redox %s image" % (env("VM_RELEASE") or "0.9.0"))
_ensure_raw()
_agent = _ensure_agent()
_ensure_tools()
_loop, _part = _attach_loop()
try:
    _inject(_part, _agent)
finally:
    subprocess.run(["sudo", "losetup", "-d", _loop], capture_output=True)
_reconvert()
log("prepareImage: done. The booted image will start /usr/bin/anyvmd on tcp:0.0.0.0:23")
