// anyvmd -- the anyvm agent for Redox OS 0.9.0.
//
// Redox ships no remote-access server, so this is it: a telnet server that
// runs commands and moves tar streams, built as a #![no_std] binary that talks
// to the kernel directly.
//
// WHY no_std, AND WHY THAT IS NOT A LIMITATION
// --------------------------------------------
// The 0.9.0 kernel has NO process-creation syscall -- verified against the
// release-day kernel commit (9673fa26b6c0, 2024-09-07): its syscall dispatch
// table has no CLONE, no FEXEC, no SPAWN, no FORK. Spawning moved entirely
// into userspace, into the `redox-rt` crate, which is itself `#![no_std]` and
// calls itself a "Libc-independent runtime". So this agent links redox-rt and
// gets real process creation without ever linking the relibc CRT
// (relibc_start_v1), which is the thing that UD2s on this frozen image.
//
// TWO STDIO PATHS, ON PURPOSE
// ---------------------------
// relibc dispatches fd queries on the fd's SCHEME and understands only tcp,
// udp and chan (src/platform/redox/socket.rs:186-197). Hand a child a raw TCP
// socket as its stdio and anything that asks about its terminal -- `ls` sizing
// its columns, any shell -- goes down the tcp arm and blocks forever on an
// answer smolnetd never sends. Measured: `ls /bin` and `ion -c` both sat in
// state UB (User Blocked) after ~0.01s of CPU. On a pty both run normally.
//
// But a pty is a terminal, and a terminal must not carry a tar archive. So:
//
//   commands  -> /bin/ion -c "<line>"  with stdio on a PTY   (needs a terminal)
//   tar       -> /bin/tar              with stdio on the SOCKET (must stay binary)
//
// tar never queries the terminal -- it was verified working with a raw socket
// as stdio before the pty was introduced -- so the split costs nothing and
// keeps the archive bytes away from any line discipline.
//
// bash cannot be used at all, whatever we do: it probes stdin with
// getpeername() to detect being run from inetd, and relibc panics rather than
// returning ENOTSOCK for a non-socket fd. Verified:
//   RELIBC PANIC: socket.rs:194: socket Ok("/scheme/pty/18") doesn't match
//   either tcp, udp or chan schemes
// No single fd is both a socket and a terminal, so bash is out. ion is Redox's
// own shell, does no such probe, and handles `&&` and `;`.

#![no_std]
#![no_main]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::fmt::Write as _;
use core::sync::atomic::{AtomicUsize, Ordering};

use redox_rt::proc::{fexec_impl, new_child_process, ExtraInfo, FdGuard, FexecResult};
use syscall::flag::{O_CLOEXEC, O_CREAT, O_NONBLOCK, O_RDONLY, O_RDWR};

// Port 23 -- the telnet port, and the one every VM_TRANSPORT=telnet guest in
// this fleet uses (plan9's telnetd, reactos' anyvmtd.exe). build.py emits
// `hostfwd=tcp:127.0.0.1:<VM_SSH_PORT>-192.168.122.254:23` when the conf sets
// VM_TRANSPORT=telnet, and anyvm.py's telnet runtime forwards to 23 too, so a
// single number serves both the build and the released image.
//
// It was briefly 22: this repo's build.py used to be a stale pre-VM_TRANSPORT
// copy that always forwarded to 22 no matter what the conf said. Replacing it
// with base-builder's put the guest port back to 23, and an agent left on 22
// is simply unreachable -- the hostfwd's host side still binds (slirp does
// that the moment QEMU starts), so it fails as a silent timeout, not an error.
const PORT_SPEC: &[u8] = b"/0.0.0.0:23";
const MARKER: &[u8] = b"anyvm-tar-done\r\n";

// ---- allocator -------------------------------------------------------------
// redox-rt needs `alloc`: fexec_impl reads the program headers into a Vec and
// builds a small BTreeMap. Nothing it allocates is re-read after free, so a
// leaking bump allocator is enough. 16-byte minimum alignment sidesteps
// plain::from_bytes' requirement on the phdr buffer.

const ARENA_SIZE: usize = 256 * 1024;
static mut ARENA: [u8; ARENA_SIZE] = [0; ARENA_SIZE];
static ARENA_OFF: AtomicUsize = AtomicUsize::new(0);

struct Bump;

unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = if layout.align() < 16 { 16 } else { layout.align() };
        let mut cur = ARENA_OFF.load(Ordering::Relaxed);
        loop {
            let base = core::ptr::addr_of!(ARENA) as usize;
            let start = (base + cur + align - 1) & !(align - 1);
            let end = start - base + layout.size();
            if end > ARENA_SIZE {
                return core::ptr::null_mut();
            }
            match ARENA_OFF.compare_exchange_weak(cur, end, Ordering::Relaxed,
                                                  Ordering::Relaxed) {
                Ok(_) => return start as *mut u8,
                Err(c) => cur = c,
            }
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOC: Bump = Bump;

// The arena is per-boot and every spawn leaks a little of it. Reset it between
// commands: nothing redox-rt allocates outlives the fexec that made it.
fn arena_reset() {
    ARENA_OFF.store(0, Ordering::Relaxed);
}

// ---- diagnostics -----------------------------------------------------------
// Redox writes nothing to the QEMU serial port (its console is the
// framebuffer), so /scheme/debug is for a human watching the VM; the useful
// channel during bring-up is the socket. Formatting is into a fixed buffer --
// never alloc::format! (the arena is shared with fexec_impl) and never
// redox_rt::sys::* (it reads a TCB this binary does not have).

static DBG: AtomicUsize = AtomicUsize::new(usize::MAX);

struct Line {
    buf: [u8; 256],
    len: usize,
}

impl core::fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if self.len < self.buf.len() {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
        Ok(())
    }
}

fn dbg_out(msg: &[u8]) {
    let fd = DBG.load(Ordering::Relaxed);
    if fd != usize::MAX {
        let _ = syscall::write(fd, msg);
    }
}

macro_rules! dbgf {
    ($($arg:tt)*) => {{
        let mut l = Line { buf: [0u8; 256], len: 0 };
        let _ = write!(l, "anyvmd: ");
        let _ = write!(l, $($arg)*);
        let _ = write!(l, "\n");
        let n = l.len;
        dbg_out(&l.buf[..n]);
    }};
}

// ---- telnet ----------------------------------------------------------------
// Not decoration: anyvm's tar stream is binary, and 0xFF is IAC. Inbound
// doubled IACs are collapsed and negotiation is answered; outbound IACs are
// doubled. BINARY (RFC 856) is requested both ways up front.

const IAC: u8 = 255;
const SE: u8 = 240;
const SB: u8 = 250;
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO: u8 = 253;
const DONT: u8 = 254;
const OPT_BINARY: u8 = 0;

struct Telnet {
    sock: usize,
    /// carry state across reads: 1 = saw IAC, 2 = saw IAC+verb, 3 = in subneg
    st: u8,
    verb: u8,
}

impl Telnet {
    fn new(sock: usize) -> Self {
        let mut t = Telnet { sock, st: 0, verb: 0 };
        let hello = [IAC, WILL, OPT_BINARY, IAC, DO, OPT_BINARY];
        t.raw_write(&hello);
        t
    }

    fn raw_write(&mut self, b: &[u8]) {
        let mut off = 0;
        while off < b.len() {
            match syscall::write(self.sock, &b[off..]) {
                Ok(0) | Err(_) => return,
                Ok(n) => off += n,
            }
        }
    }

    /// Write application data, doubling IAC so a 0xFF byte in a tar archive
    /// cannot be read as a command.
    fn write(&mut self, data: &[u8]) {
        let mut chunk = [0u8; 1024];
        let mut n = 0;
        for &b in data {
            chunk[n] = b;
            n += 1;
            if b == IAC {
                chunk[n] = IAC;
                n += 1;
            }
            if n >= chunk.len() - 1 {
                let c = chunk;
                self.raw_write(&c[..n]);
                n = 0;
            }
        }
        if n > 0 {
            let c = chunk;
            self.raw_write(&c[..n]);
        }
    }

    /// Strip telnet framing from `src`, appending application bytes to `dst`.
    /// Returns how many application bytes were produced.
    fn unescape(&mut self, src: &[u8], dst: &mut [u8]) -> usize {
        let mut out = 0;
        for &b in src {
            match self.st {
                0 => {
                    if b == IAC {
                        self.st = 1;
                    } else if out < dst.len() {
                        dst[out] = b;
                        out += 1;
                    }
                }
                1 => {
                    if b == IAC {
                        // a doubled IAC is one literal 0xFF
                        if out < dst.len() {
                            dst[out] = IAC;
                            out += 1;
                        }
                        self.st = 0;
                    } else if b == SB {
                        self.st = 3;
                    } else if b == WILL || b == WONT || b == DO || b == DONT {
                        self.verb = b;
                        self.st = 2;
                    } else {
                        self.st = 0;
                    }
                }
                2 => {
                    // Refuse everything except BINARY, which we want in both
                    // directions so the tar stream survives.
                    let reply = match self.verb {
                        DO => if b == OPT_BINARY { WILL } else { WONT },
                        WILL => if b == OPT_BINARY { DO } else { DONT },
                        _ => 0,
                    };
                    if reply != 0 {
                        let r = [IAC, reply, b];
                        self.raw_write(&r);
                    }
                    self.st = 0;
                }
                _ => {
                    // inside a subnegotiation; it ends at IAC SE
                    if b == SE {
                        self.st = 0;
                    }
                }
            }
        }
        out
    }
}

// ---- entry -----------------------------------------------------------------
// Nothing runs before e_entry: the kernel sets RIP/RSP directly and [rsp] is
// argc, not a return address. fsbase is 0 -- no TCB -- which is fine because
// nothing on the spawn path reads fs:. Only redox_rt::signal/sys/thread do,
// and none of those are called.

core::arch::global_asm!(
    ".globl _start",
    "_start:",
    "  xor rbp, rbp",
    "  mov rdi, rsp",
    "  and rsp, -16",
    "  call {main}",
    "  ud2",
    main = sym rust_start,
);

#[no_mangle]
unsafe extern "C" fn rust_start(_sp: *const usize) -> ! {
    serve();
    let _ = syscall::exit(0);
    loop {}
}

// ---- spawning --------------------------------------------------------------

/// Spawn `path`, with fds 0/1/2 bound to `stdio`, and wait for it.
/// Returns the raw wait status, or usize::MAX if it never exited.
/// `pump_to` is drained into the telnet stream while waiting (the pty master);
/// pass usize::MAX when the child writes straight to the socket itself.
fn spawn_and_wait(cur_ft: &FdGuard, t: &mut Telnet, stdio: usize, pump_to: usize,
                  path: &str, args: &[&[u8]], envs_in: &[&[u8]], cwd: Option<&[u8]>)
    -> syscall::Result<usize>
{
    // 0/1/2 must be right BEFORE the snapshot: there is no per-fd insertion
    // API for another context, so the child's table can only be a copy of ours.
    for target in 0..3usize {
        let _ = syscall::dup2(stdio, target, b"");
    }

    // argc+envc must be ODD or the child's initial sp is not 16-aligned and it
    // dies on its first movaps with no message. Pad here so no caller has to
    // remember the rule.
    let mut env_buf: [&[u8]; 8] = [b""; 8];
    let mut nenv = 0usize;
    for e in envs_in {
        if nenv < env_buf.len() - 1 {
            env_buf[nenv] = e;
            nenv += 1;
        }
    }
    if (args.len() + nenv) % 2 == 0 {
        env_buf[nenv] = b"ANYVM_PAD=1";
        nenv += 1;
    }
    let envs = &env_buf[..nenv];

    let new_ft = FdGuard::new(syscall::dup(**cur_ft, b"copy")?);
    let (child, pid) = new_child_process()?;
    // A SECOND handle: fexec_impl takes open_via_dup by value and its FdGuard
    // closes it, but we still need the first one for current-filetable/start.
    let child_exec = FdGuard::new(syscall::dup(*child, b"open_via_dup")?);

    // /scheme/memory must be a real fd -- the !0 anonymous shortcut only
    // exists on the SYS_FMAP fast path.
    let memory = FdGuard::new(syscall::open("/scheme/memory", 0)?);
    let image = FdGuard::new(syscall::open(path, O_RDONLY | O_CLOEXEC)?);

    let size: usize = args.iter().map(|a| a.len()).sum::<usize>()
        + envs.iter().map(|e| e.len()).sum::<usize>()
        + args.len() + envs.len();
    let xi = ExtraInfo {
        cwd: Some(cwd.unwrap_or(b"/")),
        sigignmask: 0,
        sigprocmask: 0,
    };

    // Reversed, matching relibc's own caller (platform/redox/exec.rs:32):
    // the loader pushes onto a downward-growing stack.
    let addrspace_handle = match fexec_impl(image, child_exec, &memory,
                                            path.as_bytes(),
                                            args.iter().rev(), envs.iter().rev(),
                                            size, &xi, None)? {
        FexecResult::Normal { addrspace_handle } => addrspace_handle,
        FexecResult::Interp { .. } => {
            dbgf!("{} is dynamic; not supported", path);
            return Ok(usize::MAX);
        }
    };

    // Both installs happen on close(), not on write().
    drop(addrspace_handle);
    {
        let sel = FdGuard::new(syscall::dup(*child, b"current-filetable")?);
        syscall::write(*sel, &usize::to_ne_bytes(*new_ft))?;
        drop(sel);
    }
    drop(new_ft);

    let start = FdGuard::new(syscall::dup(*child, b"start")?);
    syscall::write(*start, &[0])?;
    drop(start);

    // Poll, pumping on every turn. A blocking wait would stall the output of a
    // long-running command until it exited.
    let mut status = 0usize;
    let mut buf = [0u8; 1024];
    for _ in 0..(4 * 600) {
        if pump_to != usize::MAX {
            while let Ok(n) = syscall::read(pump_to, &mut buf) {
                if n == 0 { break; }
                t.write(&buf[..n]);
            }
        }
        match syscall::waitpid(pid, &mut status, syscall::flag::WNOHANG) {
            Ok(0) => {}
            Ok(_) => {
                if pump_to != usize::MAX {
                    while let Ok(n) = syscall::read(pump_to, &mut buf) {
                        if n == 0 { break; }
                        t.write(&buf[..n]);
                    }
                }
                return Ok(status);
            }
            Err(_) => return Ok(usize::MAX),
        }
        let req = syscall::TimeSpec { tv_sec: 0, tv_nsec: 250_000_000 };
        let mut rem = syscall::TimeSpec { tv_sec: 0, tv_nsec: 0 };
        let _ = syscall::nanosleep(&req, &mut rem);
    }
    Ok(usize::MAX)
}

// ---- command dispatch ------------------------------------------------------

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > hay.len() { return None; }
    for i in 0..=(hay.len() - needle.len()) {
        if &hay[i..i + needle.len()] == needle { return Some(i); }
    }
    None
}

/// Pull the first single-quoted run out of a command line -- the guest path in
/// anyvm's tar lines, which are always `... '<dir>' ...`.
fn quoted<'a>(line: &'a [u8], out: &'a mut [u8]) -> Option<&'a [u8]> {
    let a = find(line, b"'")? + 1;
    let rest = &line[a..];
    let b = find(rest, b"'")?;
    let n = if b > out.len() { out.len() } else { b };
    out[..n].copy_from_slice(&rest[..n]);
    Some(&out[..n])
}

struct Ctx {
    cur_ft: FdGuard,
    pty_master: usize,
    pty_slave: usize,
    sock: usize,
}

const ENVS: [&[u8]; 4] = [b"PATH=/bin", b"HOME=/root", b"USER=root", b"TERM=dumb"];

/// Run one command line from the host. Returns true when the connection
/// should be closed afterwards.
///
/// A tar transfer always ends the connection. tar stops at the end-of-archive
/// blocks but anyvm pads the stream, so bytes are still in flight when the
/// child exits -- and left on the socket they become the next "command line".
/// The failed first run showed exactly that, with ion reporting
/// `command not found: justcheck.txt`. Draining instead would mean a blocking
/// read on an empty socket, which would wedge the agent; closing is both safe
/// and what the host does anyway, since _tar_push_telnet opens its own
/// connection for the transfer and drops it once the marker arrives.
fn dispatch(c: &Ctx, t: &mut Telnet, line: &[u8]) -> bool {
    arena_reset();
    let mut dirbuf = [0u8; 256];

    // tar EXTRACT. The archive bytes follow on this same connection, so tar
    // must read the socket directly -- routing binary through the pty would
    // hand it to a line discipline. tar never queries the terminal (verified:
    // it ran fine with a raw socket as stdio), so this is safe.
    if find(line, b"tar -xf -").is_some() || find(line, b"tar x").is_some() {
        let dir = match quoted(line, &mut dirbuf) {
            Some(d) => d,
            None => { t.write(b"anyvmd: no directory in tar line\r\n"); return false; }
        };
        // mkdir -p through the shell; it is a terminal-safe operation and
        // saves reimplementing mkdir -p here.
        let mut mk = [0u8; 320];
        let pre = b"mkdir -p '";
        mk[..pre.len()].copy_from_slice(pre);
        let mut n = pre.len();
        mk[n..n + dir.len()].copy_from_slice(dir);
        n += dir.len();
        mk[n] = b'\'';
        n += 1;
        let mkargs: [&[u8]; 3] = [b"ion", b"-c", &mk[..n]];
        let _ = spawn_and_wait(&c.cur_ft, t, c.pty_slave, c.pty_master,
                               "/bin/ion", &mkargs, &ENVS, None);

        arena_reset();
        // `x`, not `-xf -`. Redox's tar is the old BSD form and rejects the
        // GNU spelling outright: "tar: -xf: unknown operation / need to
        // specify c[f] (create), t[f] (list), or x[f] (extract)". The f is
        // optional there, and without it tar reads stdin, which is the socket.
        let targs: [&[u8]; 2] = [b"tar", b"x"];
        let st = spawn_and_wait(&c.cur_ft, t, c.sock, usize::MAX,
                                "/bin/tar", &targs, &ENVS, Some(dir));
        // Put our own stdio back before answering.
        for i in 0..3usize { let _ = syscall::dup2(c.sock, i, b""); }
        if let Ok(s) = st {
            if s != usize::MAX && (s & 0xff00) == 0 {
                t.write(MARKER);
                return true;
            }
        }
        t.write(b"anyvmd: tar extract failed\r\n");
        return true;
    }

    // tar CREATE -- same reasoning, the other direction.
    if find(line, b"tar -cf -").is_some() || find(line, b"tar c").is_some() {
        let dir = match quoted(line, &mut dirbuf) {
            Some(d) => d,
            None => { t.write(b"anyvmd: no directory in tar line\r\n"); return false; }
        };
        let targs: [&[u8]; 3] = [b"tar", b"c", b"."];
        let _ = spawn_and_wait(&c.cur_ft, t, c.sock, usize::MAX,
                               "/bin/tar", &targs, &ENVS, Some(dir));
        for i in 0..3usize { let _ = syscall::dup2(c.sock, i, b""); }
        return true;
    }

    // Everything else is a real shell line. ion, on a pty, because a shell on
    // a raw socket blocks forever in relibc's terminal query.
    let args: [&[u8]; 3] = [b"ion", b"-c", line];
    let _ = spawn_and_wait(&c.cur_ft, t, c.pty_slave, c.pty_master,
                           "/bin/ion", &args, &ENVS, None);
    for i in 0..3usize { let _ = syscall::dup2(c.sock, i, b""); }
    false
}

// ---- the server ------------------------------------------------------------

fn serve() {
    if let Ok(fd) = syscall::open("/scheme/debug", O_RDWR) {
        DBG.store(fd, Ordering::Relaxed);
    }

    // Bind. netshell's verified sequence: open the generic scheme, dup with a
    // LEADING SLASH to bind, dup with "listen" to accept.
    let listener;
    let mut tries = 0;
    loop {
        let opened = syscall::open("tcp:", O_RDWR)
            .or_else(|_| syscall::open("/scheme/tcp", O_RDWR));
        match opened {
            Ok(fd) => match syscall::dup(fd, PORT_SPEC) {
                Ok(l) => { let _ = syscall::close(fd); listener = l; break; }
                Err(_) => { let _ = syscall::close(fd); }
            },
            Err(_) => {}
        }
        tries += 1;
        if tries >= 120 {
            dbgf!("could not bind port 23; giving up");
            return;
        }
        let req = syscall::TimeSpec { tv_sec: 1, tv_nsec: 0 };
        let mut rem = syscall::TimeSpec { tv_sec: 0, tv_nsec: 0 };
        let _ = syscall::nanosleep(&req, &mut rem);
    }
    dbgf!("listening on 0.0.0.0:23");

    // One pty for the whole run. relibc's own openpty: open /scheme/pty for
    // the master, fpath() it to learn the slave path, open that.
    let master = match syscall::open("/scheme/pty", O_RDWR | O_NONBLOCK)
        .or_else(|_| syscall::open("/scheme/pty", O_CREAT | O_RDWR | O_NONBLOCK)) {
        Ok(m) => m,
        Err(e) => { dbgf!("no pty available (errno {}); commands will not run", e.errno); return; }
    };
    let mut namebuf = [0u8; 128];
    let slave = match syscall::fpath(master, &mut namebuf) {
        Ok(n) => match core::str::from_utf8(&namebuf[..n]) {
            Ok(p) => match syscall::open(p, O_RDWR) {
                Ok(s) => s,
                Err(e) => { dbgf!("open(pty slave) errno {}", e.errno); return; }
            },
            Err(_) => { dbgf!("pty path is not utf-8"); return; }
        },
        Err(e) => { dbgf!("fpath(pty) errno {}", e.errno); return; }
    };

    let cur_ctx = match syscall::open("/scheme/thisproc/current/open_via_dup", O_CLOEXEC) {
        Ok(f) => FdGuard::new(f),
        Err(e) => { dbgf!("open(thisproc) errno {}", e.errno); return; }
    };
    let cur_ft = match syscall::dup(*cur_ctx, b"filetable") {
        Ok(f) => FdGuard::new(f),
        Err(e) => { dbgf!("dup(filetable) errno {}", e.errno); return; }
    };
    drop(cur_ctx);

    loop {
        let sock = match syscall::dup(listener, b"listen") {
            Ok(s) => s,
            Err(_) => {
                let req = syscall::TimeSpec { tv_sec: 1, tv_nsec: 0 };
                let mut rem = syscall::TimeSpec { tv_sec: 0, tv_nsec: 0 };
                let _ = syscall::nanosleep(&req, &mut rem);
                continue;
            }
        };
        dbgf!("connection accepted");
        let ctx = Ctx { cur_ft: FdGuard::new(match syscall::dup(*cur_ft, b"") {
                            Ok(f) => f, Err(_) => { let _ = syscall::close(sock); continue; } }),
                        pty_master: master, pty_slave: slave, sock };
        let mut t = Telnet::new(sock);

        // Read command lines. The agent deliberately never echoes what it was
        // sent: anyvm's readiness and tar markers are matched in the reply
        // stream, and an echo of the command line would match them itself.
        let mut cmd = [0u8; 4096];
        let mut clen = 0usize;
        let mut raw = [0u8; 1024];
        let mut app = [0u8; 1024];
        let mut done = false;
        while !done {
            let n = match syscall::read(sock, &mut raw) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let m = t.unescape(&raw[..n], &mut app);
            for i in 0..m {
                if done { break; }
                let b = app[i];
                if b == b'\n' {
                    // strip a trailing CR
                    let mut end = clen;
                    if end > 0 && cmd[end - 1] == b'\r' { end -= 1; }
                    if end > 0 && dispatch(&ctx, &mut t, &cmd[..end]) {
                        done = true;
                        break;
                    }
                    clen = 0;
                } else if clen < cmd.len() {
                    cmd[clen] = b;
                    clen += 1;
                }
            }
        }
        dbgf!("connection closed");
        let _ = syscall::close(sock);
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let mut l = Line { buf: [0u8; 256], len: 0 };
    let _ = write!(l, "anyvmd: PANIC {}\n", info);
    let n = l.len;
    dbg_out(&l.buf[..n]);
    let _ = syscall::exit(101);
    loop {}
}
