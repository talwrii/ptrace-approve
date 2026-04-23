#!/usr/bin/env python3
"""
ptrace-clip: Run the executable currently on the clipboard under ptrace-approve.

Reads the clipboard, treats its contents as a command line (with arguments),
and execs ptrace-approve with that command. Useful for quickly running
ai-generated commands through the approval system without retyping.
"""
import shlex
import sys
import os

try:
    import pyperclip
except ImportError:
    print("ptrace-clip: pyperclip not installed", file=sys.stderr)
    print("  install with: pipx inject ptrace-approve pyperclip", file=sys.stderr)
    sys.exit(1)


def main():
    try:
        clip = pyperclip.paste()
    except pyperclip.PyperclipException as e:
        print(f"ptrace-clip: cannot read clipboard: {e}", file=sys.stderr)
        print("  on linux you may need: apt install xclip  (or xsel)", file=sys.stderr)
        sys.exit(1)

    clip = clip.strip()
    if not clip:
        print("ptrace-clip: clipboard is empty", file=sys.stderr)
        sys.exit(1)

    try:
        argv = shlex.split(clip)
    except ValueError as e:
        print(f"ptrace-clip: cannot parse clipboard as command: {e}", file=sys.stderr)
        print(f"  clipboard content: {clip!r}", file=sys.stderr)
        sys.exit(1)

    if not argv:
        print("ptrace-clip: clipboard parsed to empty command", file=sys.stderr)
        sys.exit(1)

    # Print what we're about to run so the user can confirm before approving
    print(f"ptrace-clip: running: {' '.join(shlex.quote(a) for a in argv)}",
          file=sys.stderr)

    # Pass through any args from ptrace-clip itself (e.g. --debug, --no-prompt)
    # before the clipboard command
    extra_args = sys.argv[1:]
    cmd = ["ptrace-approve"] + extra_args + argv

    try:
        os.execvp("ptrace-approve", cmd)
    except FileNotFoundError:
        print("ptrace-clip: ptrace-approve not found in PATH", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"ptrace-clip: failed to exec ptrace-approve: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()