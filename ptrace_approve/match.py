"""
Pattern matching for function-call-shaped descriptions.

Descriptions look like:
    exec(/bin/true, [/bin/true, 1])
    open(/home/me/foo.txt, create+write)
    delete(/tmp/junk)

Patterns look like:
    exec(...)                      match any exec
    exec(/bin/*, ...)              glob first arg, ignore rest
    open(_, write)                 any path, literal "write"
    open(/home/me/*, _)            glob path, any mode
    open(**/__pycache__/*, _)      ** crosses directories
    exec(//usr/bin/py.+/, ...)     /regex/ on leaf
    exec(_, [/bin/*, ...])         match inside lists too
    delete(_)                      any single-arg delete

Special tokens:
    _      matches any single argument (string or list)
    ...    matches zero or more remaining arguments
    *      in a glob, matches characters except /
    **     in a glob, matches characters including /
    /X/    leaf is matched as regex X (first and last char are /)
    other strings are literal matches
"""

import re


# ---------------------------------------------------------------------------
# Parser — turns "exec(/bin/true, [a, b])" into ("exec", ["/bin/true", ["a", "b"]])
# ---------------------------------------------------------------------------

def _tokenize(s):
    """Split into tokens: ( ) [ ] , and bare strings."""
    tokens = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch in '()[]':
            tokens.append(ch)
            i += 1
        elif ch == ',':
            tokens.append(',')
            i += 1
        elif ch in ' \t':
            i += 1
        else:
            # bare string — read until delimiter
            j = i
            while j < len(s) and s[j] not in '()[], \t':
                j += 1
            tokens.append(s[i:j])
            i = j
    return tokens


def _parse_list(tokens, pos):
    """Parse a [...] list, returns (list_of_items, new_pos)."""
    assert tokens[pos] == '['
    pos += 1
    items = []
    while pos < len(tokens) and tokens[pos] != ']':
        if tokens[pos] == ',':
            pos += 1
            continue
        item, pos = _parse_value(tokens, pos)
        items.append(item)
    if pos < len(tokens) and tokens[pos] == ']':
        pos += 1
    return items, pos


def _parse_value(tokens, pos):
    """Parse a single value: either a [...] list or a bare string."""
    if tokens[pos] == '[':
        return _parse_list(tokens, pos)
    else:
        val = tokens[pos]
        return val, pos + 1


def parse(s):
    """Parse 'name(arg1, arg2, ...)' into (name, [arg1, arg2, ...]).

    Arguments can be strings or nested lists.
    Returns (name, args).
    """
    tokens = _tokenize(s)
    if not tokens:
        return ('', [])

    # Check for name(...)
    if len(tokens) >= 2 and tokens[1] == '(':
        name = tokens[0]
        pos = 2  # skip name and (
        args = []
        while pos < len(tokens) and tokens[pos] != ')':
            if tokens[pos] == ',':
                pos += 1
                continue
            val, pos = _parse_value(tokens, pos)
            args.append(val)
        return (name, args)

    # No parens — just a string
    return (tokens[0], [])


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------

def _glob_to_regex(pattern):
    """Convert a glob pattern to a regex.

    * matches any characters except /
    ** matches zero or more path components (including /)
    ? matches a single character except /
    """
    result = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == '*' and i + 1 < n and pattern[i + 1] == '*':
            # ** — handle surrounding slashes so it can match zero components
            has_slash_before = (i > 0 and pattern[i - 1] == '/' and result and result[-1] == '/')
            has_slash_after = (i + 2 < n and pattern[i + 2] == '/')
            if has_slash_before and has_slash_after:
                # /**/  →  match "/" or "/anything/"
                result.pop()  # remove the / we already emitted
                result.append('(/.+)?/')
                i += 3  # skip ** and the trailing /
            elif has_slash_before:
                # /** at end  →  optionally /anything
                result.pop()
                result.append('(/.*)?')
                i += 2
            elif has_slash_after:
                # **/ at start  →  optionally anything/
                result.append('(.*/)?')
                i += 3
            else:
                result.append('.*')
                i += 2
        elif ch == '*':
            result.append('[^/]*')
            i += 1
        elif ch in r'\.+^${}()|[]?':
            result.append('\\' + ch)
            i += 1
        else:
            result.append(ch)
            i += 1
    return ''.join(result)


def _match_leaf(pattern, value):
    """Match a pattern string against a value string.

    - "_" matches anything (as a whole argument)
    - "..." is handled by caller
    - "/X/" matches value against regex X
    - patterns containing * are globs (* = not /, ** = anything)
    - everything else is literal
    """
    if pattern == '_':
        return True
    if len(pattern) >= 2 and pattern[0] == '/' and pattern[-1] == '/':
        regex = pattern[1:-1]
        return bool(re.fullmatch(regex, value))
    if '*' in pattern:
        return bool(re.fullmatch(_glob_to_regex(pattern), value))
    return pattern == value


def _match_args(patterns, values):
    """Match a list of pattern args against a list of value args.

    Handles ... (ellipsis) to match zero or more remaining args.
    """
    pi = 0
    vi = 0
    while pi < len(patterns):
        pat = patterns[pi]

        # ... matches all remaining
        if pat == '...':
            return True

        # ran out of values
        if vi >= len(values):
            return False

        if not _match_value(pat, values[vi]):
            return False

        pi += 1
        vi += 1

    # both exhausted?
    return vi >= len(values)


def _match_value(pattern, value):
    """Match a single pattern value against a single actual value.

    Both can be strings or lists.
    """
    # pattern is a list, value must be a list
    if isinstance(pattern, list) and isinstance(value, list):
        return _match_args(pattern, value)

    # _ matches anything including lists
    if pattern == '_':
        return True

    # pattern is a string, value is a string
    if isinstance(pattern, str) and isinstance(value, str):
        return _match_leaf(pattern, value)

    # pattern is a string (not _), value is a list — no match
    # pattern is a list, value is a string — no match
    return False


def match(pattern_str, description_str):
    """Match a pattern string against a description string.

    Returns True if the pattern matches the description.
    """
    pname, pargs = parse(pattern_str)
    dname, dargs = parse(description_str)

    if pname != dname:
        return False

    return _match_args(pargs, dargs)


def matches_any(patterns, description):
    """Return True if any pattern in the list matches the description."""
    for p in patterns:
        try:
            if match(p, description):
                return True
        except Exception:
            pass
    return False