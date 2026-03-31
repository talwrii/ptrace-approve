"""Tests for ptrace_approve.match"""

import pytest
from ptrace_approve.match import parse, match, matches_any, _match_leaf, _tokenize


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

class TestTokenize:
    def test_simple(self):
        assert _tokenize("exec(/bin/true)") == ["exec", "(", "/bin/true", ")"]

    def test_with_list(self):
        assert _tokenize("exec(/bin/true, [a, b])") == [
            "exec", "(", "/bin/true", ",", "[", "a", ",", "b", "]", ")"
        ]

    def test_spaces(self):
        assert _tokenize("open( /tmp/foo , write )") == [
            "open", "(", "/tmp/foo", ",", "write", ")"
        ]

    def test_empty(self):
        assert _tokenize("") == []

    def test_no_parens(self):
        assert _tokenize("hello") == ["hello"]

    def test_plus_in_mode(self):
        assert _tokenize("open(/tmp/f, create+write)") == [
            "open", "(", "/tmp/f", ",", "create+write", ")"
        ]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class TestParse:
    def test_simple_call(self):
        assert parse("delete(/tmp/junk)") == ("delete", ["/tmp/junk"])

    def test_two_args(self):
        assert parse("open(/tmp/foo, write)") == ("open", ["/tmp/foo", "write"])

    def test_list_arg(self):
        assert parse("exec(/bin/true, [/bin/true, 1])") == (
            "exec", ["/bin/true", ["/bin/true", "1"]]
        )

    def test_empty_args(self):
        assert parse("exec()") == ("exec", [])

    def test_no_parens(self):
        assert parse("hello") == ("hello", [])

    def test_empty_string(self):
        assert parse("") == ("", [])

    def test_nested_list(self):
        # shouldn't happen in practice but shouldn't crash
        assert parse("f([a, [b, c]])") == ("f", [["a", ["b", "c"]]])

    def test_rename(self):
        assert parse("rename(/old -> /new)") == ("rename", ["/old", "->", "/new"])


# ---------------------------------------------------------------------------
# Leaf matching
# ---------------------------------------------------------------------------

class TestMatchLeaf:
    def test_literal(self):
        assert _match_leaf("write", "write") is True
        assert _match_leaf("write", "read") is False

    def test_star(self):
        assert _match_leaf("*", "anything") is True
        assert _match_leaf("*", "") is True

    def test_glob(self):
        assert _match_leaf("/bin/*", "/bin/true") is True
        assert _match_leaf("/bin/*", "/usr/bin/true") is False
        assert _match_leaf("/home/*/projects/*", "/home/me/projects/foo") is True

    def test_glob_star_does_not_match_slash(self):
        # * should not cross directory boundaries
        assert _match_leaf("/home/*/foo", "/home/me/foo") is True
        assert _match_leaf("/home/*/foo", "/home/me/sub/foo") is False
        assert _match_leaf("*/__pycache__/*", "/home/bruger/__pycache__/foo.pyc") is False

    def test_glob_doublestar(self):
        # ** matches across directories
        assert _match_leaf("**/__pycache__/*", "/home/bruger/mine/project/__pycache__/foo.pyc") is True
        assert _match_leaf("**/__pycache__/**", "/a/b/__pycache__/c/d.pyc") is True
        assert _match_leaf("/home/**/__pycache__/*", "/home/bruger/mine/project/__pycache__/foo.pyc") is True
        assert _match_leaf("/home/**/__pycache__/*", "/home/__pycache__/foo.pyc") is True

    def test_glob_question(self):
        assert _match_leaf("/bin/tru?", "/bin/true") is True
        assert _match_leaf("/bin/tru?", "/bin/trux") is True
        assert _match_leaf("/bin/tru?", "/bin/tr") is False

    def test_glob_question_does_not_match_slash(self):
        assert _match_leaf("/bin/tru?", "/bin/tru/") is False

    def test_regex(self):
        assert _match_leaf("//bin/tr.+/", "/bin/true") is True
        assert _match_leaf("//bin/tr.+/", "/bin/false") is False

    def test_regex_no_path(self):
        assert _match_leaf("/write|read/", "write") is True
        assert _match_leaf("/write|read/", "read") is True
        assert _match_leaf("/write|read/", "execute") is False

    def test_regex_fullmatch(self):
        # regex uses fullmatch, not search
        assert _match_leaf("/bin/", "bin") is True
        assert _match_leaf("/bin/", "binary") is False


# ---------------------------------------------------------------------------
# Full match
# ---------------------------------------------------------------------------

class TestMatch:
    # --- ellipsis ---
    def test_ellipsis_matches_all(self):
        assert match("exec(...)", "exec(/bin/true, [/bin/true, 1])") is True

    def test_ellipsis_matches_none(self):
        assert match("exec(...)", "exec()") is True

    def test_ellipsis_after_arg(self):
        assert match("exec(/bin/*, ...)", "exec(/bin/true, [/bin/true, 1])") is True

    # --- glob on args ---
    def test_glob_match(self):
        assert match("exec(/bin/*, ...)", "exec(/bin/true, [/bin/true, 1])") is True

    def test_glob_no_match(self):
        assert match("exec(/usr/*, ...)", "exec(/bin/true, [/bin/true, 1])") is False

    # --- literal ---
    def test_literal_match(self):
        assert match("open(*, write)", "open(/tmp/foo, write)") is True

    def test_literal_no_match(self):
        assert match("open(*, write)", "open(/tmp/foo, read)") is False

    # --- star matches anything ---
    def test_star_matches_string(self):
        assert match("delete(*)", "delete(/tmp/junk)") is True

    def test_star_matches_list(self):
        assert match("exec(*, *)", "exec(/bin/true, [/bin/true, 1])") is True

    # --- list patterns ---
    def test_list_pattern(self):
        assert match("exec(*, [/bin/*, ...])", "exec(/bin/true, [/bin/true, 1])") is True

    def test_list_pattern_no_match(self):
        assert match("exec(*, [/usr/*, ...])", "exec(/bin/true, [/bin/true, 1])") is False

    def test_list_exact(self):
        assert match("exec(*, [/bin/true, 1])", "exec(/bin/true, [/bin/true, 1])") is True

    def test_list_wrong_length(self):
        assert match("exec(*, [/bin/true])", "exec(/bin/true, [/bin/true, 1])") is False

    # --- regex ---
    def test_regex_match(self):
        assert match("exec(//bin/tr.+/, ...)", "exec(/bin/true, [/bin/true, 1])") is True

    def test_regex_no_match(self):
        assert match("exec(//bin/tr.+/, ...)", "exec(/bin/false, [/bin/false])") is False

    # --- name mismatch ---
    def test_wrong_name(self):
        assert match("open(...)", "exec(/bin/true)") is False

    # --- arity ---
    def test_too_few_pattern_args(self):
        # pattern has fewer args than description, no ellipsis
        assert match("exec(/bin/true)", "exec(/bin/true, [/bin/true, 1])") is False

    def test_too_many_pattern_args(self):
        assert match("exec(*, *, *)", "exec(/bin/true, [/bin/true])") is False

    def test_exact_arity(self):
        assert match("open(/home/me/*, *)", "open(/home/me/foo.txt, create+write)") is True

    # --- real-world descriptions ---
    def test_open_create_write(self):
        assert match("open(/home/**, ...)", "open(/home/me/foo.txt, create+write)") is True

    def test_open_star_does_not_cross_dirs(self):
        assert match("open(/home/*, ...)", "open(/home/me/foo.txt, create+write)") is False
        assert match("open(/home/*, ...)", "open(/home/foo.txt, create+write)") is True

    def test_pycache(self):
        desc = "open(/home/bruger/mine/machine-sync/machine_sync/__pycache__/main.cpython-312.pyc.123, create+write)"
        assert match("open(**/__pycache__/*, *)", desc) is True
        assert match("open(*/__pycache__/*, *)", desc) is False

    def test_mkdir(self):
        assert match("mkdir(/tmp/*)", "mkdir(/tmp/newdir)") is True

    def test_chmod(self):
        assert match("chmod(*, *)", "chmod(/tmp/foo, 0o755)") is True

    def test_rename(self):
        assert match("rename(*, ...)", "rename(/old -> /new)") is True


# ---------------------------------------------------------------------------
# matches_any
# ---------------------------------------------------------------------------

class TestMatchesAny:
    def test_one_matches(self):
        patterns = ["open(*, write)", "exec(...)"]
        assert matches_any(patterns, "exec(/bin/ls, [/bin/ls])") is True

    def test_none_match(self):
        patterns = ["open(*, write)", "delete(*)"]
        assert matches_any(patterns, "exec(/bin/ls, [/bin/ls])") is False

    def test_empty_patterns(self):
        assert matches_any([], "exec(/bin/ls)") is False

    def test_bad_pattern_skipped(self):
        patterns = ["exec(//[invalid/)", "exec(...)"]
        assert matches_any(patterns, "exec(/bin/ls)") is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])