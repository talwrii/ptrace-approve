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
from ptrace.debugger.process_event import ProcessExecution
from ptrace.func_call import FunctionCallOptions
from ptrace.syscall import PtraceSyscall, SYSCALL_NAMES
from ptrace.tools import signal_to_exitcode

from ptrace_approve.match import matches_any

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

def prompt_user(description: str, app_key: str, profiles: dict) -> bool:
    """Ask the user what to do. Returns True to allow, False to deny."""
    print(f"\n{BOLD}{YELLOW}⚡ {description}{RESET}")
    print(f"  {CYAN}[a]{RESET} approve once   "
          f"{CYAN}[p]{RESET} add pattern   "
          f"{CYAN}[d]{RESET} deny once   "
          f"{CYAN}[D]{RESET} deny + pattern")
    while True:
        try:
            sys.stdout.write("  > ")
            sys.stdout.flush()
            ch = sys.stdin.readline().strip()
        except (EOFError, KeyboardInterrupt):
            return False
        if ch == 'a':
            print(f"  {GREEN}✓ allowed{RESET}")
            return True
        elif ch == 'p':
            pattern = input_with_default("  Pattern: ", description)
            add_pattern(profiles, app_key, pattern)
            save_profiles(profiles)
            print(f"  {GREEN}✓ pattern saved, allowed{RESET}")
            return True
        elif ch == 'd':
            print(f"  {RED}✗ denied{RESET}")
            return False
        elif ch == 'D':
            pattern = input_with_default("  Deny pattern: ", description)
            add_pattern(profiles, app_key + ":deny", pattern)
            save_profiles(profiles)
            print(f"  {RED}✗ deny pattern saved{RESET}")
            return False
        else:
            print(f"  Use a/p/d/D")

# ---------------------------------------------------------------------------
# Core ptrace loop
# ---------------------------------------------------------------------------
def run(cmd: list, app_key: str, profiles: dict, no_prompt: bool = False, log_only: bool = False, strace_file=None):
    from ptrace.debugger.child import createChild
    debugger = PtraceDebugger()
    # Don't traceFork — child process memory can't be read reliably via python-ptrace
    debugger.traceExec()

    try:
        pid = createChild(cmd, no_stdout=False)
        process = debugger.addProcess(pid, is_attached=True)
    except Exception as e:
        print(f"Error starting process: {e}", file=sys.stderr)
        sys.exit(1)

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
            exit_code = event.exitcode or 0
            break

        if isinstance(event, ProcessExecution):
            try: event.process.syscall()
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

            allow_patterns = get_patterns(profiles, app_key)
            deny_patterns  = get_patterns(profiles, app_key + ":deny")

            if matches_any(deny_patterns, desc):
                print(f"\n{RED}✗ auto-denied: {desc}{RESET}")
                _deny_syscall(proc)
                continue

            if matches_any(allow_patterns, desc):
                try: proc.syscall()
                except Exception: pass
                continue

            if no_prompt:
                print(f"\n{RED}✗ denied (no profile match): {desc}{RESET}")
                _deny_syscall(proc)
                continue

            allowed = prompt_user(desc, app_key, profiles)
            if allowed:
                try: proc.syscall()
                except Exception: pass
            else:
                _deny_syscall(proc)
        else:
            try: proc.syscall()
            except Exception: pass

    try: debugger.quit()
    except Exception: pass
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

def main():
    parser = argparse.ArgumentParser(
        description="Intercept and approve filesystem-modifying syscalls."
    )
    parser.add_argument("cmd", nargs="*", help="Command to run")
    parser.add_argument("--clear", metavar="APP",
                        help="Clear saved profile for APP")
    parser.add_argument("--clear-run", action="store_true",
                        help="Clear saved profile for the command before running it")
    parser.add_argument("--list", action="store_true",
                        help="List all saved profiles")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress startup messages")
    parser.add_argument("-P", "--no-prompt", action="store_true",
                        help="Only use saved profile — deny anything not matched, no interactive prompts")
    parser.add_argument("--log-only", action="store_true",
                        help="Log all watched syscalls as descriptions and allow everything — no prompts, no profile")
    parser.add_argument("--strace", metavar="FILE",
                        help="Log watched syscalls in strace format to FILE and allow everything — for debugging")
    args = parser.parse_args()

    if args.list:
        list_profiles()
        return

    if args.clear:
        clear_profile(args.clear)
        return

    if not args.cmd:
        parser.print_help()
        sys.exit(1)

    import shutil
    binary = shutil.which(args.cmd[0]) or args.cmd[0]
    app_key = binary
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
            patterns = get_patterns(profiles, app_key)
            if patterns:
                print(f"Loaded {len(patterns)} allow pattern(s)")
        print()

    strace_file = open(args.strace, "w") if args.strace else None
    try:
        exit_code = run(args.cmd, app_key, profiles, no_prompt=args.no_prompt, log_only=args.log_only, strace_file=strace_file)
    finally:
        if strace_file:
            strace_file.close()
    sys.exit(exit_code)

if __name__ == "__main__":
    main()