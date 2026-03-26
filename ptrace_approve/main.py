#!/usr/bin/env python3
"""
ptrace-approve: Intercept and approve filesystem-modifying syscalls.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

from ptrace.debugger import PtraceDebugger, ProcessExit, ProcessSignal
from ptrace.debugger.process_event import ProcessExecution
from ptrace.func_call import FunctionCallOptions
from ptrace.syscall import PtraceSyscall, SYSCALL_NAMES
from ptrace.tools import signal_to_exitcode

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CONFIG_DIR   = Path.home() / ".config" / "ptrace-approve"
PROFILE_FILE = CONFIG_DIR / "profiles.json"

# Syscalls we care about and how to describe them
WATCHED_SYSCALLS = {
    # name -> lambda args: description string
    "openat":    lambda a: _openat_desc(a),
    "open":      lambda a: _open_desc(a),
    "creat":     lambda a: f"create({_str(a,0)})",
    "unlink":    lambda a: f"delete({_str(a,0)})",
    "unlinkat":  lambda a: f"delete({_str(a,1)})",
    "rename":    lambda a: f"rename({_str(a,0)} -> {_str(a,1)})",
    "renameat":  lambda a: f"rename({_str(a,1)} -> {_str(a,3)})",
    "renameat2": lambda a: f"rename({_str(a,1)} -> {_str(a,3)})",
    "mkdir":     lambda a: f"mkdir({_str(a,0)})",
    "mkdirat":   lambda a: f"mkdir({_str(a,1)})",
    "rmdir":     lambda a: f"rmdir({_str(a,0)})",
    "chmod":     lambda a: f"chmod({_str(a,0)}, {_str(a,1)})",
    "fchmodat":  lambda a: f"chmod({_str(a,1)}, {_str(a,2)})",
    "execve":    lambda a: f"exec({_str(a,0)})",
    "execveat":  lambda a: f"exec({_str(a,1)})",
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
    try:
        a = args[i]
        t = a.getText()
        if t:
            # strip surrounding quotes if present
            t = t.strip("'\"")
            return t
        v = a.value
        if isinstance(v, bytes):
            return v.decode(errors='replace')
        return str(v)
    except Exception:
        return "?"

def _openat_desc(args):
    path  = _str(args, 1)
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
    path  = _str(args, 0)
    flags = _get_flags(args, 1)
    if flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC):
        mode = []
        if flags & O_CREAT:  mode.append("create")
        if flags & O_TRUNC:  mode.append("truncate")
        if flags & O_WRONLY: mode.append("write")
        if flags & O_RDWR:   mode.append("read-write")
        return f"open({path}, {'+'.join(mode)})"
    return None

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

def preprocess_pattern(pattern: str) -> str:
    """Replace unescaped . with [^,)] so dots don't match , or ) by default."""
    result = []
    i = 0
    in_class = False
    while i < len(pattern):
        ch = pattern[i]
        if ch == '\\':
            # escaped char — pass through both chars unchanged
            result.append(ch)
            if i + 1 < len(pattern):
                result.append(pattern[i + 1])
                i += 2
            else:
                i += 1
        elif ch == '[':
            in_class = True
            result.append(ch)
            i += 1
        elif ch == ']':
            in_class = False
            result.append(ch)
            i += 1
        elif ch == '.' and not in_class:
            result.append('[^,)]')
            i += 1
        else:
            result.append(ch)
            i += 1
    return ''.join(result)


def matches_any(patterns: list, description: str) -> bool:
    for p in patterns:
        try:
            if re.search(preprocess_pattern(p), description):
                return True
        except re.error:
            pass
    return False

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
        # Fallback if readline unavailable
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
            ch = sys.stdin.readline().strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False

        if ch == 'a':
            print(f"  {GREEN}✓ allowed{RESET}")
            return True

        elif ch == 'p':
            suggested = re.escape(description)
            pattern = input_with_default("  Pattern (regexp): ", suggested)
            try:
                re.compile(preprocess_pattern(pattern))
                add_pattern(profiles, app_key, pattern)
                save_profiles(profiles)
                print(f"  {GREEN}✓ pattern saved, allowed{RESET}")
                return True
            except re.error as e:
                print(f"  {RED}Invalid regexp: {e}{RESET}")
                # loop back

        elif ch == 'd':
            print(f"  {RED}✗ denied{RESET}")
            return False

        elif ch in ('d', 'D') or ch == 'D':
            suggested = re.escape(description)
            pattern = input_with_default("  Deny pattern (regexp): ", suggested)
            try:
                re.compile(preprocess_pattern(pattern))
                # Store deny patterns with a prefix
                add_pattern(profiles, app_key + ":deny", pattern)
                save_profiles(profiles)
                print(f"  {RED}✗ deny pattern saved{RESET}")
                return False
            except re.error as e:
                print(f"  {RED}Invalid regexp: {e}{RESET}")

        else:
            print(f"  Use a/p/d/D")

# ---------------------------------------------------------------------------
# Core ptrace loop
# ---------------------------------------------------------------------------
def run(cmd: list, app_key: str, profiles: dict, no_prompt: bool = False):
    from ptrace.debugger.child import createChild
    debugger = PtraceDebugger()
    debugger.traceFork()
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

    from ptrace.debugger.process_event import NewProcessEvent
    from signal import SIGTRAP, SIGSTOP
    SYSCALL_STOP = SIGTRAP | 0x80  # sysgood bit set = syscall-stop

    exit_code = 0
    active = 1

    while active > 0:
        try:
            event = debugger.waitProcessEvent()
        except Exception:
            break

        if isinstance(event, ProcessExit):
            exit_code = event.exitcode or 0
            active -= 1
            continue

        if isinstance(event, NewProcessEvent):
            active += 1
            try: event.process.syscall()
            except Exception: pass
            try: event.process.parent.syscall()
            except Exception: pass
            continue

        if isinstance(event, ProcessExecution):
            try: event.process.syscall()
            except Exception: pass
            continue

        if isinstance(event, ProcessSignal):
            signum = event.signum
            if signum in (SIGTRAP, SIGSTOP, SYSCALL_STOP):
                # syscall-stop or attach-stop — treat as syscall event below
                proc = event.process
            else:
                # real signal — forward it
                try: event.process.syscall(signum)
                except Exception: pass
                continue
        else:
            proc = event.process

        # Process syscall entry/exit
        try:
            syscall = proc.syscall_state.event(syscall_options)
        except Exception:
            try: proc.syscall()
            except Exception: pass
            continue

        # skip exit side or empty
        if syscall is None or syscall.result is not None:
            try: proc.syscall()
            except Exception: pass
            continue

        name = syscall.name
        if name in WATCHED_SYSCALLS:
            try:
                desc = WATCHED_SYSCALLS[name](syscall.arguments)
            except Exception:
                desc = name

            if desc is None:
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
        # On x86_64, syscall number is in orig_rax
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
    # Resolve to full path like main() does
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
    parser.add_argument("--list", action="store_true",
                        help="List all saved profiles")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress startup messages")
    parser.add_argument("-P", "--no-prompt", action="store_true",
                        help="Only use saved profile — deny anything not matched, no interactive prompts")

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

    # Resolve app key from binary path
    import shutil
    binary = shutil.which(args.cmd[0]) or args.cmd[0]
    app_key = binary

    profiles = load_profiles()

    if not args.quiet:
        print(f"{CYAN}ptrace-approve{RESET}: watching {BOLD}{' '.join(args.cmd)}{RESET}")
        print(f"Profile: {app_key}")
        patterns = get_patterns(profiles, app_key)
        if patterns:
            print(f"Loaded {len(patterns)} allow pattern(s)")
        print()

    exit_code = run(args.cmd, app_key, profiles, no_prompt=args.no_prompt)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()