#!/usr/bin/env python3
"""
ptrace-approve: Intercept and approve filesystem-modifying syscalls.
"""
import argparse
import json
import logging
import os
import re
import struct
import sys
from pathlib import Path
from typing import Optional

from ptrace.debugger import PtraceDebugger, ProcessExit, ProcessSignal
from ptrace.debugger.process_event import ProcessExecution, NewProcessEvent
from ptrace.func_call import FunctionCallOptions
from ptrace.syscall import PtraceSyscall, SYSCALL_NAMES
from ptrace.tools import signal_to_exitcode

from ptrace_approve.match import matches_any, find_match

# Suppress python-ptrace's noisy logging for transient read failures
logging.getLogger().setLevel(logging.CRITICAL)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CONFIG_DIR   = Path.home() / ".config" / "ptrace-approve"
PROFILE_FILE = CONFIG_DIR / "profiles.json"

# Syscalls we care about and how to describe them
WATCHED_SYSCALLS = {
    # name -> lambda args, proc: description string
    "openat":    lambda a, p: _openat_desc(a),
    "open":      lambda a, p: _open_desc(a),
    "creat":     lambda a, p: f"create({_str(a,0)})" if _str(a,0) else None,
    "unlink":    lambda a, p: f"delete({_str(a,0)})" if _str(a,0) else None,
    "unlinkat":  lambda a, p: f"delete({_str(a,1)})" if _str(a,1) else None,
    "rename":    lambda a, p: f"rename({_str(a,0)} -> {_str(a,1)})" if _str(a,0) and _str(a,1) else None,
    "renameat":  lambda a, p: f"rename({_str(a,1)} -> {_str(a,3)})" if _str(a,1) and _str(a,3) else None,
    "renameat2": lambda a, p: f"rename({_str(a,1)} -> {_str(a,3)})" if _str(a,1) and _str(a,3) else None,
    "mkdir":     lambda a, p: f"mkdir({_str(a,0)})" if _str(a,0) else None,
    "mkdirat":   lambda a, p: f"mkdir({_str(a,1)})" if _str(a,1) else None,
    "rmdir":     lambda a, p: f"rmdir({_str(a,0)})" if _str(a,0) else None,
    "chmod":     lambda a, p: f"chmod({_str(a,0)}, {_str(a,1)})" if _str(a,0) else None,
    "fchmodat":  lambda a, p: f"chmod({_str(a,1)}, {_str(a,2)})" if _str(a,1) else None,
    "execve":    lambda a, p: _execve_desc(a, p),
    "execveat":  lambda a, p: _execveat_desc(a, p),
}

def _get_flags(args, i):
    """Get open flags as integer, handling both int value and text like O_WRONLY|O_CREAT."""
    try:
        return int(args[i].value)
    except Exception:
        pass
    try:
        t = args[i].getText() or ""
        flags = 0
        if "O_WRONLY"  in t: flags |= O_WRONLY
        if "O_RDWR"   in t: flags |= O_RDWR
        if "O_CREAT"  in t: flags |= O_CREAT
        if "O_TRUNC"  in t: flags |= O_TRUNC
        return flags
    except Exception:
        return 0

O_WRONLY = 0x1
O_RDWR   = 0x2
O_CREAT  = 0x40
O_TRUNC  = 0x200

def _str(args, i):
    """Read a string argument from syscall args."""
    try:
        a = args[i]
        t = a.getText()
        if t:
            t = t.strip("'\"")
            return t
        v = a.value
        if isinstance(v, bytes):
            return v.decode(errors='replace')
        if isinstance(v, int):
            return None
        return str(v)
    except Exception:
        return None

def _openat_desc(args):
    path = _str(args, 1)
    if path is None:
        return None
    flags = _get_flags(args, 2)
    if flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC):
        mode = []
        if flags & O_CREAT:  mode.append("create")
        if flags & O_TRUNC:  mode.append("truncate")
        if flags & O_WRONLY: mode.append("write")
        if flags & O_RDWR:   mode.append("read-write")
        return f"open({path}, {'+'.join(mode)})"
    return None  # read-only, skip

def _open_desc(args):
    path = _str(args, 0)
    if path is None:
        return None
    flags = _get_flags(args, 1)
    if flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC):
        mode = []
        if flags & O_CREAT:  mode.append("create")
        if flags & O_TRUNC:  mode.append("truncate")
        if flags & O_WRONLY: mode.append("write")
        if flags & O_RDWR:   mode.append("read-write")
        return f"open({path}, {'+'.join(mode)})"
    return None

def _read_argv(proc, addr):
    """Read argv char** from process memory, return formatted [arg, arg, 'arg with spaces']."""
    parts = []
    offset = 0
    while len(parts) < 20:
        try:
            raw = proc.readBytes(addr + offset, 8)
            ptr = struct.unpack('<Q', bytes(raw))[0]
            if ptr == 0:
                break
            s = proc.readCString(ptr, 300)
            if isinstance(s, tuple):
                s = s[0]
            if isinstance(s, bytes):
                s = s.decode(errors='replace')
            if re.search(r'[\s,\[\]\'"]', s):
                s = f"'{s}'"
            parts.append(s)
            offset += 8
        except Exception as e:
            print(f"DEBUG _read_argv offset={offset} addr={addr:#x}: {e}", file=sys.stderr)
            break
    return '[' + ', '.join(parts) + ']' if parts else ''

def _execve_desc(args, proc):
    path = _str(args, 0)
    if path is None:
        return None
    try:
        argv = _read_argv(proc, args[1].value)
    except Exception:
        argv = ''
    return f"exec({path}, {argv})" if argv else f"exec({path})"

def _execveat_desc(args, proc):
    path = _str(args, 1)
    if path is None:
        return None
    try:
        argv = _read_argv(proc, args[2].value)
    except Exception:
        argv = ''
    return f"exec({path}, {argv})" if argv else f"exec({path})"

# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------
def load_profiles() -> dict:
    if not PROFILE_FILE.exists():
        return {}
    with open(PROFILE_FILE) as f:
        return json.load(f)

def save_profiles(profiles: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(PROFILE_FILE, "w") as f:
        json.dump(profiles, f, indent=2)

def get_patterns(profiles: dict, app_key: str) -> list:
    return profiles.get(app_key, [])

def add_pattern(profiles: dict, app_key: str, pattern: str):
    if app_key not in profiles:
        profiles[app_key] = []
    if pattern not in profiles[app_key]:
        profiles[app_key].append(pattern)

# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
CYAN   = '\033[96m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
RED    = '\033[91m'
RESET  = '\033[0m'
BOLD   = '\033[1m'

def input_with_default(prompt: str, default: str) -> str:
    """Input with a pre-filled editable default using readline."""
    try:
        import readline
        def pre_input_hook():
            readline.insert_text(default)
            readline.redisplay()
        readline.set_pre_input_hook(pre_input_hook)
        try:
            result = input(prompt)
        finally:
            readline.set_pre_input_hook(None)
        return result
    except Exception:
        sys.stdout.write(f"{prompt}[{default}]: ")
        sys.stdout.flush()
        line = sys.stdin.readline().strip()
        return line if line else default

class NoBlockError(Exception):
    """Raised when prompt_user would block but PTAPP_NO_BLOCK is set."""
    def __init__(self, description: str):
        self.description = description
        super().__init__(description)

def prompt_user(description: str, app_key: str, profiles: dict, pid: int = None, initial_pid: int = None):
    """Ask the user what to do. Returns True to allow, False to deny, None to quit, 'trust' to trust pid."""
    if os.environ.get("PTAPP_NO_BLOCK"):
        raise NoBlockError(description)
    if pid is not None and initial_pid is not None:
        chain = _proc_chain(pid, initial_pid)
        print(f"\n{BOLD}{YELLOW}⚡ {description}{RESET}")
        print(f"  {CYAN}{chain}{RESET}")
    elif pid is not None:
        print(f"\n{BOLD}{YELLOW}⚡ {description}{RESET} {CYAN}(pid {pid}){RESET}")
    else:
        print(f"\n{BOLD}{YELLOW}⚡ {description}{RESET}")
    print(f"  {CYAN}[a]{RESET} approve once   "
          f"{CYAN}[p]{RESET} add pattern   "
          f"{CYAN}[c]{RESET} allow child   "
          f"{CYAN}[d]{RESET} deny once   "
          f"{CYAN}[D]{RESET} deny + pattern")
    print(f"  {CYAN}[t]{RESET} tree   "
          f"{CYAN}[q]{RESET} quit")
    while True:
        try:
            sys.stdout.write("  > ")
            sys.stdout.flush()
            ch = sys.stdin.readline().strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if ch == 'a':
            print(f"  {GREEN}✓ allowed{RESET}")
            return True
        elif ch == 'p':
            pattern = input_with_default("  Pattern: ", description)
            add_pattern(profiles, app_key, pattern)
            save_profiles(profiles)
            print(f"  {GREEN}✓ pattern saved, allowed{RESET}")
            return True
        elif ch == 'c':
            if pid is not None:
                print(f"  {GREEN}✓ pid {pid} trusted for this session{RESET}")
                return 'trust'
            else:
                print(f"  {YELLOW}(no pid info){RESET}")
        elif ch == 'd':
            print(f"  {RED}✗ denied{RESET}")
            return False
        elif ch == 'D':
            pattern = input_with_default("  Deny pattern: ", description)
            add_pattern(profiles, app_key + ":deny", pattern)
            save_profiles(profiles)
            print(f"  {RED}✗ deny pattern saved{RESET}")
            return False
        elif ch == 't':
            if pid is not None:
                print(f"  {CYAN}{_proc_chain(pid)}{RESET}")
            else:
                print(f"  {YELLOW}(no pid info){RESET}")
        elif ch == 'q':
            print(f"  {RED}quit{RESET}")
            return None
        else:
            print(f"  Use a/p/c/d/D/t/q")

# ---------------------------------------------------------------------------
# Background (file-based) approval
# ---------------------------------------------------------------------------
import time as _time

_background_seq = 0

def _background_approve(description: str, app_key: str, profiles: dict, background_dir: str, pid: int = None):
    """Write a pending approval request and block until a matching response appears."""
    global _background_seq
    _background_seq += 1
    seq = _background_seq

    bg = Path(background_dir)
    pending = bg / "pending.json"
    response = bg / "response.json"

    request = {
        "seq": seq,
        "description": description,
        "app_key": app_key,
        "pid": pid,
    }
    # Atomic write: tmp then rename
    tmp = bg / "pending.tmp"
    tmp.write_text(json.dumps(request, indent=2))
    tmp.rename(pending)

    # Block until a response with matching seq appears
    while True:
        if response.exists():
            try:
                resp = json.loads(response.read_text())
            except (json.JSONDecodeError, OSError):
                _time.sleep(0.1)
                continue

            if resp.get("seq") != seq:
                # Stale response — ignore
                _time.sleep(0.1)
                continue

            pending.unlink(missing_ok=True)
            response.unlink(missing_ok=True)

            action = resp.get("action", "deny")
            if action == "approve":
                return True
            elif action == "pattern":
                pattern = resp.get("pattern", description)
                add_pattern(profiles, app_key, pattern)
                save_profiles(profiles)
                return True
            elif action == "trust":
                return "trust"
            elif action == "deny":
                return False
            elif action == "deny_pattern":
                pattern = resp.get("pattern", description)
                add_pattern(profiles, app_key + ":deny", pattern)
                save_profiles(profiles)
                return False
            elif action == "quit":
                return None
            else:
                return False
        _time.sleep(0.2)

def background_respond(background_dir: str, seq: int, action: str, pattern: str = None):
    """Write a response file, then wait for the process to finish or need approval again.
    Prints JSON status. If process finishes, exits with the process's exit code.
    If another approval is needed, exits 0.
    """
    bg = Path(background_dir)
    response = bg / "response.json"
    resp = {"seq": seq, "action": action}
    if pattern is not None:
        resp["pattern"] = pattern
    tmp = bg / "response.tmp"
    tmp.write_text(json.dumps(resp, indent=2))
    tmp.rename(response)

    # Now wait for the next event (pending or done)
    pending = bg / "pending.json"
    done_file = bg / "done.json"

    while True:
        # Check done first — if the process finished, we don't want to report
        # a stale pending.json
        if done_file.exists():
            try:
                data = json.loads(done_file.read_text())
            except (json.JSONDecodeError, OSError):
                _time.sleep(0.2)
                continue
            data["status"] = "done"
            print(json.dumps(data))
            sys.exit(data.get("exit_code", 0))

        if pending.exists():
            try:
                data = json.loads(pending.read_text())
            except (json.JSONDecodeError, OSError):
                _time.sleep(0.2)
                continue
            # Only report pending if it's newer than the seq we just responded to
            if data.get("seq", 0) <= seq:
                _time.sleep(0.2)
                continue
            data["status"] = "pending"
            print(json.dumps(data))
            return

        _time.sleep(0.2)

def background_wait(background_dir: str):
    """Block until the background process needs approval or is done.
    Always exits 0. Prints JSON with either {"status": "pending", "seq": ..., ...}
    or {"status": "done", "exit_code": ...}.
    """
    bg = Path(background_dir)
    pending = bg / "pending.json"
    done_file = bg / "done.json"

    while True:
        if pending.exists():
            try:
                data = json.loads(pending.read_text())
            except (json.JSONDecodeError, OSError):
                _time.sleep(0.2)
                continue
            data["status"] = "pending"
            print(json.dumps(data))
            return

        if done_file.exists():
            try:
                data = json.loads(done_file.read_text())
            except (json.JSONDecodeError, OSError):
                _time.sleep(0.2)
                continue
            data["status"] = "done"
            print(json.dumps(data))
            return

        _time.sleep(0.2)

# ---------------------------------------------------------------------------
# Core ptrace loop
# ---------------------------------------------------------------------------
def _proc_cmdline(pid):
    """Read command line for a pid from /proc."""
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        return ' '.join(raw.decode(errors='replace').split('\0')).strip()
    except Exception:
        return "?"

def _proc_ppid(pid):
    """Read parent pid from /proc."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        return int(stat.split(') ')[1].split()[1])
    except Exception:
        return None

def _proc_chain(pid, stop_pid=None):
    """Build ancestry chain: pid(cmd) ← ppid(cmd) ← ... stopping at stop_pid or init."""
    parts = []
    seen = set()
    current = pid
    while current and current > 1 and current not in seen:
        seen.add(current)
        cmd = _proc_cmdline(current)
        # shorten to just the binary name
        short = cmd.split()[0].rsplit('/', 1)[-1] if cmd and cmd != '?' else '?'
        parts.append(f"{current}({short})")
        if current == stop_pid:
            break
        current = _proc_ppid(current)
    return ' ← '.join(parts)

def _unwrap_ptrace_shebang(cmd: list, explicit_profile: Optional[str]):
    """If cmd[0] has a ptrace-approve shebang, strip it to avoid nested tracing.

    Returns (new_cmd, profile_from_shebang_or_None).
    """
    import shutil
    binary = shutil.which(cmd[0]) or cmd[0]
    try:
        with open(binary, "rb") as f:
            first_line = f.readline(512)
    except (OSError, IsADirectoryError):
        return cmd, None
    if not first_line.startswith(b"#!"):
        return cmd, None
    shebang = first_line.decode("utf-8", errors="replace").rstrip("\n")
    m = re.match(
        r'^#!/usr/bin/env -S ptrace-approve\s+(?:--profile\s+(\S+)\s+)?--\s+(.+)$',
        shebang,
    )
    if not m:
        return cmd, None
    wrapped_profile = m.group(1)
    interpreter_parts = m.group(2).strip().split()
    new_cmd = interpreter_parts + [binary] + list(cmd[1:])
    return new_cmd, (explicit_profile or wrapped_profile)


def run(cmd: list, app_key: str, profiles: dict, no_prompt: bool = False, log_only: bool = False, strace_file=None, debug: bool = False, trace_children: bool = False, background_dir: str = None):
    from ptrace.debugger.child import createChild
    debugger = PtraceDebugger()
    debugger.traceFork()
    debugger.traceExec()

    try:
        pid = createChild(cmd, no_stdout=False)
        initial_pid = pid
        process = debugger.addProcess(pid, is_attached=True)
    except Exception as e:
        print(f"Error starting process: {e}", file=sys.stderr)
        sys.exit(1)

    if debug:
        print(f"{CYAN}initial pid: {initial_pid}{RESET}")

    trusted_pids = set()
    own_pids = {initial_pid}  # pids that forked from us but haven't exec'd

    process.syscall()
    syscall_options = FunctionCallOptions(
        write_types=False,
        write_argname=False,
        string_max_length=300,
        replace_socketcall=True,
        write_address=False,
        max_array_count=20,
    )

    from signal import SIGTRAP, SIGSTOP
    SYSCALL_STOP = SIGTRAP | 0x80  # sysgood bit set = syscall-stop
    exit_code = 0

    while True:
        try:
            event = debugger.waitProcessEvent()
        except Exception:
            break

        if isinstance(event, ProcessExit):
            own_pids.discard(event.process.pid)
            trusted_pids.discard(event.process.pid)
            if event.process.pid == initial_pid:
                exit_code = event.exitcode or 0
                break
            else:
                continue

        if isinstance(event, ProcessExecution):
            proc = event.process
            if proc.pid != initial_pid:
                own_pids.discard(proc.pid)
                if not trace_children:
                    # exec'd — we approved it, now let it run free
                    if debug:
                        print(f"  {CYAN}detach: pid {proc.pid} exec'd ({_proc_cmdline(proc.pid)}){RESET}")
                    try: proc.detach()
                    except Exception: pass
                    continue
                else:
                    if debug:
                        print(f"  {CYAN}exec: pid {proc.pid} left own_pids ({_proc_cmdline(proc.pid)}){RESET}")
            try: proc.syscall()
            except Exception: pass
            continue

        if isinstance(event, NewProcessEvent):
            new_proc = event.process
            # child inherits "own" status from parent
            if new_proc.parent is not None and new_proc.parent.pid in own_pids:
                own_pids.add(new_proc.pid)
                if debug:
                    print(f"  {CYAN}fork: pid {new_proc.pid} added to own_pids (parent {new_proc.parent.pid}){RESET}")
            elif debug:
                print(f"  {CYAN}fork: pid {new_proc.pid} (child, not own){RESET}")
            try: new_proc.syscall()
            except Exception: pass
            if new_proc.parent is not None:
                try: new_proc.parent.syscall()
                except Exception: pass
            continue

        if isinstance(event, ProcessSignal):
            signum = event.signum
            if signum in (SIGTRAP, SIGSTOP, SYSCALL_STOP):
                proc = event.process
            else:
                try: event.process.syscall(signum)
                except Exception: pass
                continue
        else:
            proc = event.process

        try:
            syscall = proc.syscall_state.event(syscall_options)
        except Exception:
            try: proc.syscall()
            except Exception: pass
            continue

        if syscall is None or syscall.result is not None:
            try: proc.syscall()
            except Exception: pass
            continue

        name = syscall.name
        if name in WATCHED_SYSCALLS:
            # Child process memory can't be read reliably — skip but log
            # own_pids: forked from us but not yet exec'd — treat as ours
            # Exception: exec calls are important to approve regardless of pid
            # With -f/--trace-children: approve everything from all pids
            if not trace_children and proc.pid not in own_pids and name not in ("execve", "execveat"):
                if debug:
                    print(f"  {CYAN}skip: pid {proc.pid} ({_proc_cmdline(proc.pid)}) {name}{RESET}")
                try: proc.syscall()
                except Exception: pass
                continue

            if strace_file:
                try:
                    pid = proc.pid
                    fmt = syscall.format()
                except Exception:
                    fmt = name
                    pid = "?"
            try:
                desc = WATCHED_SYSCALLS[name](syscall.arguments, proc)
            except Exception:
                desc = None

            if strace_file:
                strace_file.write(f"[pid {pid}] {fmt}  # {desc}\n")
                strace_file.flush()

            if desc is None:
                try: proc.syscall()
                except Exception: pass
                continue

            if log_only:
                print(desc)
                try: proc.syscall()
                except Exception: pass
                continue

            # Trusted child — previously approved with 'c'
            if proc.pid in trusted_pids:
                if debug:
                    print(f"  {GREEN}✓ trusted child (pid {proc.pid}): {desc}{RESET}")
                try: proc.syscall()
                except Exception: pass
                continue

            allow_patterns = get_patterns(profiles, app_key)
            deny_patterns  = get_patterns(profiles, app_key + ":deny")

            deny_rule = find_match(deny_patterns, desc)
            if deny_rule is not None:
                print(f"\n{RED}✗ auto-denied: {desc}{RESET}")
                if debug:
                    print(f"  {CYAN}pid: {proc.pid}  rule: {deny_rule}{RESET}")
                _deny_syscall(proc)
                continue

            allow_rule = find_match(allow_patterns, desc)
            if allow_rule is not None:
                if debug:
                    print(f"  {GREEN}✓ auto-allowed (pid {proc.pid}): {desc}{RESET}")
                    print(f"  {CYAN}rule: {allow_rule}{RESET}")
                try: proc.syscall()
                except Exception: pass
                continue

            if no_prompt:
                if debug:
                    print(f"  {YELLOW}? no matching rule (pid {proc.pid}): {desc}{RESET}")
                print(f"\n{RED}✗ denied (no profile match): {desc}{RESET}")
                _deny_syscall(proc)
                continue

            if debug:
                print(f"  {YELLOW}? no matching rule (pid {proc.pid}): {desc}{RESET}")

            try:
                if background_dir:
                    allowed = _background_approve(desc, app_key, profiles, background_dir, pid=proc.pid)
                else:
                    allowed = prompt_user(desc, app_key, profiles, pid=proc.pid, initial_pid=initial_pid if debug else None)
            except NoBlockError as e:
                # PTAPP_NO_BLOCK is set — kill the whole tree and exit 3
                print(f"{RED}ERROR: ptrace-approve needs approval for: {e.description}{RESET}", file=sys.stderr)
                print(f"  PTAPP_NO_BLOCK is set. Re-run with --background-dir DIR (see `ptrace-approve --skill` for protocol).", file=sys.stderr)
                try:
                    for p in list(debugger):
                        try: p.kill(9)
                        except Exception: pass
                except Exception: pass
                try: debugger.quit()
                except Exception: pass
                sys.exit(3)
            if allowed is None:
                # quit — kill the child and bail
                exit_code = 130
                try: proc.kill(9)
                except Exception: pass
                break
            elif allowed == 'trust':
                trusted_pids.add(proc.pid)
                try: proc.syscall()
                except Exception: pass
            elif allowed:
                try: proc.syscall()
                except Exception: pass
            else:
                _deny_syscall(proc)
        else:
            try: proc.syscall()
            except Exception: pass

    try: debugger.quit()
    except Exception: pass

    if background_dir:
        done_file = Path(background_dir) / "done.json"
        done_file.write_text(json.dumps({"exit_code": exit_code}))

    return exit_code

def _deny_syscall(proc):
    """Replace syscall number with -1 to make it a no-op, return EPERM."""
    try:
        regs = proc.getregs()
        regs.orig_rax = 0xffffffffffffffff  # invalid syscall
        proc.setregs(regs)
    except Exception:
        pass
    proc.syscall()

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def clear_profile(app_key: str):
    import shutil
    resolved = shutil.which(app_key) or app_key
    profiles = load_profiles()
    removed = False
    for key in [resolved, resolved + ":deny", app_key, app_key + ":deny"]:
        if key in profiles:
            del profiles[key]
            removed = True
    if removed:
        save_profiles(profiles)
        print(f"Cleared profile for {resolved}")
    else:
        print(f"No profile found for {resolved}")

def show_rules(app_key: str):
    import shutil
    resolved = shutil.which(app_key) or app_key
    profiles = load_profiles()
    allow = get_patterns(profiles, resolved)
    deny = get_patterns(profiles, resolved + ":deny")
    if not allow and not deny:
        print(f"No rules for {resolved}")
    else:
        print(f"{BOLD}{resolved}{RESET}")
        if allow:
            print(f"\n  {GREEN}allow:{RESET}")
            for p in allow:
                print(f"    {p}")
        if deny:
            print(f"\n  {RED}deny:{RESET}")
            for p in deny:
                print(f"    {p}")

def list_profiles():
    profiles = load_profiles()
    if not profiles:
        print("No profiles saved.")
        return
    for app_key, patterns in profiles.items():
        kind = "deny" if app_key.endswith(":deny") else "allow"
        base = app_key.removesuffix(":deny")
        print(f"\n{BOLD}{base}{RESET} ({kind}):")
        for p in patterns:
            print(f"  {p}")

SKILL_TEXT = """ptrace-approve background mode (for AI/non-interactive drivers)

Setup:
  export PTAPP_NO_BLOCK=1      # makes interactive prompts exit 3 instead of hanging

Protocol:
  ptrace-approve --background-dir DIR -- CMD &         # start subprocess
  ptrace-approve --background-wait DIR                 # block for next event, prints JSON
  ptrace-approve --background-respond DIR SEQ ACTION   # reply, then wait for next event

Events (JSON on stdout):
  {"seq": N, "description": "...", "app_key": "...", "pid": N, "status": "pending"}
  {"status": "done", "exit_code": N}

Actions for --background-respond:
  approve                      # allow this call, ask again next time
  deny                         # block this call, ask again next time
  pattern --background-pattern P       # allow + save P to profile
  deny_pattern --background-pattern P  # deny + save P to deny list
  trust                        # allow + add exact match to profile
  quit                         # kill the traced process

Pattern syntax (for P):
  exec(/path/to/bin, [argv0, arg1, ...])     exec call
  open(/path, mode)                          open/openat
  mkdir(/path)  unlink(/path)  rename(a -> b)   other syscalls
  *            any single path segment (no /)
  **           any path including /
  _            any single argv arg
  ...          all remaining argv args (trailing only)
  "*"          literal asterisk
  /regex/      regex (commas/slashes are separators)

Exit codes:
  --background-wait:      exits 0 after printing any event
  --background-respond:   exits 0 during run, exits with subprocess's exit code when done
  PTAPP_NO_BLOCK without --background-dir: exits 3
"""


def main():
    parser = argparse.ArgumentParser(
        description="Intercept and approve filesystem-modifying syscalls.",
        epilog="""Non-interactive / AI driver mode:
  Run `ptrace-approve --skill` for full protocol, actions, and pattern syntax.
  Short version: set PTAPP_NO_BLOCK=1, then drive with
  --background-dir / --background-wait / --background-respond.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("cmd", nargs="*", help="Command to run")
    parser.add_argument("--clear", metavar="APP",
                        help="Clear saved profile for APP")
    parser.add_argument("--clear-run", action="store_true",
                        help="Clear saved profile for the command before running it")
    parser.add_argument("--list", action="store_true",
                        help="List all saved profiles")
    parser.add_argument("--rules", metavar="APP",
                        help="Show saved rules for APP")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress startup messages")
    parser.add_argument("-P", "--no-prompt", action="store_true",
                        help="Only use saved profile — deny anything not matched, no interactive prompts")
    parser.add_argument("--log-only", action="store_true",
                        help="Log all watched syscalls as descriptions and allow everything — no prompts, no profile")
    parser.add_argument("--strace", metavar="FILE",
                        help="Log watched syscalls in strace format to FILE and allow everything — for debugging")
    parser.add_argument("--debug", action="store_true",
                        help="Show every approved/denied syscall and the rule that matched")
    parser.add_argument("-f", "--trace-children", action="store_true",
                        help="Require approval for all children's syscalls, not just exec")
    parser.add_argument("--profile", metavar="NAME",
                        help="Use NAME as the profile key instead of the resolved binary path")
    parser.add_argument("--background-dir", metavar="DIR",
                        help="Run in background mode: write approval requests to DIR instead of prompting")
    parser.add_argument("--background-wait", metavar="DIR",
                        help="Wait for a background process in DIR to need approval or finish")
    parser.add_argument("--background-respond", nargs=3, metavar=("DIR", "SEQ", "ACTION"),
                        help="Respond to a pending approval: DIR SEQ ACTION (approve/pattern/trust/deny/deny_pattern/quit)")
    parser.add_argument("--background-pattern", metavar="PATTERN",
                        help="Pattern to use with --background-respond pattern/deny_pattern actions")
    parser.add_argument("--skill", action="store_true",
                        help="Print AI-driver skill doc (protocol, actions, pattern syntax) and exit")
    args = parser.parse_args()

    if args.skill:
        print(SKILL_TEXT, end="")
        return

    if args.background_wait:
        background_wait(args.background_wait)
        return

    if args.background_respond:
        bg_dir, seq_str, action = args.background_respond
        background_respond(bg_dir, int(seq_str), action, pattern=args.background_pattern)
        return

    if args.list:
        list_profiles()
        return

    if args.clear:
        clear_profile(args.clear)
        return

    if args.rules:
        show_rules(args.rules)
        return

    if not args.cmd:
        parser.print_help()
        sys.exit(1)

    args.cmd, shebang_profile = _unwrap_ptrace_shebang(args.cmd, args.profile)
    import shutil
    binary = shutil.which(args.cmd[0]) or args.cmd[0]
    app_key = args.profile or shebang_profile or binary
    profiles = load_profiles()

    if args.clear_run:
        removed = False
        for key in [binary, binary + ":deny"]:
            if key in profiles:
                del profiles[key]
                removed = True
        if removed:
            save_profiles(profiles)
            if not args.quiet:
                print(f"Cleared profile for {binary}")

    if not args.quiet:
        if args.log_only:
            print(f"{CYAN}ptrace-approve{RESET}: logging {BOLD}{' '.join(args.cmd)}{RESET} (all allowed)")
        elif args.strace:
            print(f"{CYAN}ptrace-approve{RESET}: watching {BOLD}{' '.join(args.cmd)}{RESET} (strace → {args.strace})")
            print(f"Profile: {app_key}")
            patterns = get_patterns(profiles, app_key)
            if patterns:
                print(f"Loaded {len(patterns)} allow pattern(s)")
        else:
            print(f"{CYAN}ptrace-approve{RESET}: watching {BOLD}{' '.join(args.cmd)}{RESET}")
            print(f"Profile: {app_key}")
            allow = get_patterns(profiles, app_key)
            deny = get_patterns(profiles, app_key + ":deny")
            if args.debug:
                if allow:
                    print(f"  {GREEN}allow ({len(allow)}):{RESET}")
                    for p in allow:
                        print(f"    {p}")
                if deny:
                    print(f"  {RED}deny ({len(deny)}):{RESET}")
                    for p in deny:
                        print(f"    {p}")
                if not allow and not deny:
                    print(f"  (no rules)")
            else:
                if allow:
                    print(f"Loaded {len(allow)} allow pattern(s)")
        print()

    bg_dir = args.background_dir
    if bg_dir:
        Path(bg_dir).mkdir(parents=True, exist_ok=True)

    strace_file = open(args.strace, "w") if args.strace else None
    try:
        exit_code = run(args.cmd, app_key, profiles, no_prompt=args.no_prompt, log_only=args.log_only, strace_file=strace_file, debug=args.debug, trace_children=args.trace_children, background_dir=bg_dir)
    finally:
        if strace_file:
            strace_file.close()

    sys.exit(exit_code)

if __name__ == "__main__":
    main()