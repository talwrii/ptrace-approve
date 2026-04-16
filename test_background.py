"""Integration tests for ptrace-approve's background mode.

These tests spawn real subprocesses under ptrace-approve and drive the
file-based approval protocol end-to-end.
"""
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

PTRACE_APPROVE = "ptrace-approve"


def _ptrace_available():
    return shutil.which(PTRACE_APPROVE) is not None


pytestmark = pytest.mark.skipif(
    not _ptrace_available(),
    reason="ptrace-approve not installed on PATH",
)


@pytest.fixture
def bg_dir(tmp_path):
    d = tmp_path / "bg"
    d.mkdir()
    yield d


@pytest.fixture
def target_file(tmp_path):
    f = tmp_path / "target"
    yield f


def _start_bg(bg_dir, cmd, extra_args=None):
    """Start ptrace-approve in background mode. Returns the Popen handle."""
    args = [PTRACE_APPROVE, "--background-dir", str(bg_dir), "-q", "--clear-run"]
    if extra_args:
        args.extend(extra_args)
    args.append("--")
    args.extend(cmd)
    return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _wait(bg_dir, timeout=10):
    """Call --background-wait and return parsed JSON."""
    r = subprocess.run(
        [PTRACE_APPROVE, "--background-wait", str(bg_dir)],
        capture_output=True, text=True, timeout=timeout
    )
    assert r.returncode == 0, f"background-wait failed: {r.stderr}"
    return json.loads(r.stdout.strip())


def _respond(bg_dir, seq, action, pattern=None, timeout=10):
    """Call --background-respond and return (exit_code, parsed JSON)."""
    args = [PTRACE_APPROVE, "--background-respond", str(bg_dir), str(seq), action]
    if pattern:
        args.extend(["--background-pattern", pattern])
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    data = json.loads(r.stdout.strip()) if r.stdout.strip() else None
    return r.returncode, data


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestBackgroundMode:

    def test_approve_single_write(self, bg_dir, target_file):
        """touch a file, approve the open, process finishes with exit 0."""
        proc = _start_bg(bg_dir, ["touch", str(target_file)])
        try:
            event = _wait(bg_dir)
            assert event["status"] == "pending"
            assert event["seq"] == 1
            assert "open" in event["description"]
            assert str(target_file) in event["description"]

            exit_code, done = _respond(bg_dir, 1, "approve")
            assert exit_code == 0
            assert done["status"] == "done"
            assert done["exit_code"] == 0
            assert target_file.exists()
        finally:
            proc.wait(timeout=5)

    def test_deny_blocks_write(self, bg_dir, target_file):
        """Denied syscall — file should not be created."""
        proc = _start_bg(bg_dir, ["touch", str(target_file)])
        try:
            event = _wait(bg_dir)
            assert event["status"] == "pending"

            # touch may call open() multiple times on failure, so keep denying
            last_exit = None
            while event["status"] == "pending":
                exit_code, event = _respond(bg_dir, event["seq"], "deny")
                last_exit = exit_code
                if event["status"] == "done":
                    break

            assert event["status"] == "done"
            # touch exits non-zero when the open is denied
            assert last_exit != 0
            assert not target_file.exists()
        finally:
            proc.wait(timeout=5)

    def test_done_has_exit_code_zero_on_success(self, bg_dir, tmp_path):
        """/bin/true has no approvable syscalls — should finish immediately."""
        proc = _start_bg(bg_dir, ["/bin/true"])
        try:
            event = _wait(bg_dir, timeout=5)
            assert event["status"] == "done"
            assert event["exit_code"] == 0
        finally:
            proc.wait(timeout=5)

    def test_done_has_exit_code_nonzero_on_failure(self, bg_dir, tmp_path):
        """/bin/false should return exit 1."""
        proc = _start_bg(bg_dir, ["/bin/false"])
        try:
            event = _wait(bg_dir, timeout=5)
            assert event["status"] == "done"
            assert event["exit_code"] == 1
        finally:
            proc.wait(timeout=5)

    def test_seq_numbers_increment(self, bg_dir, tmp_path):
        """Multiple approvals get unique, incrementing seq numbers."""
        f1 = tmp_path / "f1"
        f2 = tmp_path / "f2"
        # Use sh to chain two touch calls — each should trigger approval
        proc = _start_bg(bg_dir, ["sh", "-c", f"touch {f1} && touch {f2}"])
        try:
            seqs = []
            event = _wait(bg_dir)
            while event["status"] == "pending":
                seqs.append(event["seq"])
                # approve everything with a pattern so we don't loop forever
                exit_code, event = _respond(bg_dir, event["seq"], "approve")
                if event["status"] == "done":
                    break

            assert event["status"] == "done"
            # Seq numbers should be strictly increasing, starting at 1
            assert seqs[0] == 1
            for i in range(1, len(seqs)):
                assert seqs[i] == seqs[i - 1] + 1
            # Both files should have been created
            assert f1.exists()
            assert f2.exists()
        finally:
            proc.wait(timeout=10)

    def test_ptapp_no_block_exits_3(self, tmp_path):
        """PTAPP_NO_BLOCK should cause exit 3 without blocking on stdin."""
        target = tmp_path / "nobloc"
        env = dict(os.environ)
        env["PTAPP_NO_BLOCK"] = "1"
        r = subprocess.run(
            [PTRACE_APPROVE, "-q", "--clear-run", "--", "touch", str(target)],
            capture_output=True, text=True, timeout=10, env=env,
            stdin=subprocess.DEVNULL,
        )
        assert r.returncode == 3
        assert "PTAPP_NO_BLOCK" in r.stderr
        assert "--background-dir" in r.stderr
        assert not target.exists()

    def test_stale_response_ignored(self, bg_dir, tmp_path):
        """Writing a response with a wrong seq shouldn't be picked up."""
        target = tmp_path / "stale"
        proc = _start_bg(bg_dir, ["touch", str(target)])
        try:
            event = _wait(bg_dir)
            assert event["status"] == "pending"
            real_seq = event["seq"]

            # Write a stale response with wrong seq directly to the file
            (bg_dir / "response.json").write_text(
                json.dumps({"seq": real_seq + 99, "action": "approve"})
            )
            time.sleep(0.5)

            # pending should still be there
            assert (bg_dir / "pending.json").exists()

            # Remove stale response, write correct one
            (bg_dir / "response.json").unlink()
            exit_code, done = _respond(bg_dir, real_seq, "approve")
            assert exit_code == 0
            assert done["status"] == "done"
        finally:
            proc.wait(timeout=5)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
