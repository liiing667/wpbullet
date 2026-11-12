import re

# User-controlled input sources. Single source of truth, mirrored by
# core.modules.BaseClass.user_input so modules keep their extension point.
USER_INPUT = [
    "\\$_GET",
    "\\$_POST",
    "\\$_REQUEST",
    "\\$_FILES",
    "\\$_COOKIE",
    "\\$_SERVER(\\s?)\\[(\\s?)+('|\\\"|`)(REQUEST_URI|PHP_SELF|HTTP_REFERER)(\\s?)+('|\\\"|`)(\\s?)+]",
    "\\$_SESSION"
]

# Constructs the lightweight engine cannot analyze precisely. When any of
# these are present the engine degrades to conservative (over-approximating)
# results so potential vulnerabilities are still reported.
DEGRADING_CONSTRUCTS = re.compile(
    r"(\$\$|\bextract\s*\(|\bparse_str\s*\(|\bmb_parse_str\s*\()",
    flags=re.IGNORECASE
)

# $var, $var->prop (array offsets handled separately)
VAR_TOKEN = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*(?:->[A-Za-z_][A-Za-z0-9_]*)?")

# $var = ..., $var .= ..., $var =& ..., $arr['k'] = ..., $obj->prop = ...
ASSIGN = re.compile(
    r"(\$[A-Za-z_][A-Za-z0-9_]*(?:->[A-Za-z_][A-Za-z0-9_]*)?(?:\[[^\]]*\])?)"
    r"\s*(\.=|=&|=)(?![=>])\s*([^;]*)"
)

FUNCTION_DECL = re.compile(r"\bfunction\s*[A-Za-z_0-9]*\s*\(")

GLOBAL_DECL = re.compile(r"\bglobal\s+((?:\$[A-Za-z_0-9]+\s*,?\s*)+)")


# Replaces comments and string literal contents with spaces while preserving
# newlines (so line numbers stay intact). Variable tokens ($var, $_GET['x'])
# inside strings are kept verbatim: they are interpolated by PHP in
# double-quoted strings and keeping them elsewhere is conservative.
# Content that is out of scope for the lightweight sanitizer (heredoc/nowdoc)
# is copied verbatim so potential matches are still reported.
def sanitize_content(content):
    out = []
    i = 0
    n = len(content)
    state = 'code'
    quote = ''
    while i < n:
        ch = content[i]
        nxt = content[i + 1] if i + 1 < n else ''
        if state == 'code':
            if ch == '/' and nxt == '/':
                state = 'line_comment'
                out.append('  ')
                i += 2
            elif ch == '#':
                state = 'line_comment'
                out.append(' ')
                i += 1
            elif ch == '/' and nxt == '*':
                state = 'block_comment'
                out.append('  ')
                i += 2
            elif ch == "'" or ch == '"':
                state = 'string'
                quote = ch
                out.append(ch)
                i += 1
            elif ch == '<' and content.startswith('<<<', i):
                # Heredoc/nowdoc: out of scope, keep verbatim (conservative)
                out.append(content[i:])
                break
            else:
                out.append(ch)
                i += 1
        elif state == 'string':
            if ch == '\\' and nxt:
                out.append('  ')
                i += 2
            elif ch == quote:
                state = 'code'
                out.append(ch)
                i += 1
            elif ch == '$' and (nxt.isalpha() or nxt == '_' or ord(nxt or ' ') > 127):
                token, i = _read_variable(content, i)
                out.append(token)
            elif ch == '\n':
                out.append('\n')
                i += 1
            else:
                out.append(' ')
                i += 1
        elif state == 'line_comment':
            if ch == '\n':
                state = 'code'
                out.append('\n')
            else:
                out.append(' ')
            i += 1
        elif state == 'block_comment':
            if ch == '*' and nxt == '/':
                state = 'code'
                out.append('  ')
                i += 2
            elif ch == '\n':
                out.append('\n')
                i += 1
            else:
                out.append(' ')
                i += 1
    return ''.join(out)


# Reads a $variable token (including one array offset) starting at pos.
def _read_variable(content, pos):
    n = len(content)
    i = pos + 1
    while i < n and (content[i].isalnum() or content[i] == '_' or ord(content[i]) > 127):
        i += 1
    if i < n and content[i] == '[':
        end = content.find(']', i)
        if end != -1:
            i = end + 1
    return content[pos:i], i


class _Scope(object):
    def __init__(self):
        self.vars = {}
        self.globals = set()


# Lightweight scope-aware taint analysis. Returns a list of regex-escaped
# variable patterns (with word-boundary guards) whose content may be
# controlled by user input. When the code contains constructs the engine
# cannot analyze, every variable is returned (conservative alerting).
def get_tainted_variables(content, sources=None):
    source_re = re.compile('|'.join(sources or USER_INPUT), flags=re.IGNORECASE)
    sanitized = sanitize_content(content)

    scopes = [_Scope()]
    brace_stack = []
    pending_function = False
    degraded = False
    all_vars = set()
    tainted = set()

    for line in sanitized.split('\n'):
        if DEGRADING_CONSTRUCTS.search(line):
            degraded = True

        all_vars.update(VAR_TOKEN.findall(line))

        if FUNCTION_DECL.search(line):
            pending_function = True

        global_match = GLOBAL_DECL.search(line)
        if global_match:
            for var in re.findall(r"\$[A-Za-z_0-9]+", global_match.group(1)):
                scopes[-1].globals.add(var)
                if scopes[0].vars.get(var):
                    scopes[-1].vars[var] = True

        for match in ASSIGN.finditer(line):
            lhs, op, rhs = match.group(1), match.group(2), match.group(3)
            is_element = '[' in lhs
            var = lhs[:lhs.index('[')] if is_element else lhs
            rhs_tainted = _expr_tainted(rhs, scopes, source_re)
            _assign(scopes, var, op, is_element, rhs_tainted)

        saw_open = False
        for ch in line:
            if ch == '{':
                saw_open = True
                brace_stack.append('func' if pending_function else 'block')
                if pending_function:
                    scopes.append(_Scope())
                pending_function = False
            elif ch == '}':
                if brace_stack:
                    kind = brace_stack.pop()
                    if kind == 'func' and len(scopes) > 1:
                        tainted.update(v for v, t in scopes[-1].vars.items() if t)
                        scopes.pop()
        if ';' in line and not saw_open:
            pending_function = False

    for scope in scopes:
        tainted.update(v for v, t in scope.vars.items() if t)

    if degraded:
        # Out of analyzable scope: conservative over-approximation
        tainted = all_vars

    return [re.escape(var) + r"(?![A-Za-z0-9_])" for var in sorted(tainted)]


def _assign(scopes, var, op, is_element, rhs_tainted):
    targets = [scopes[-1]]
    if var in scopes[-1].globals:
        targets.append(scopes[0])
    for scope in targets:
        if op == '.=':
            scope.vars[var] = scope.vars.get(var, False) or rhs_tainted
        elif is_element and not rhs_tainted:
            # Clean element assignment keeps previous taint (conservative)
            scope.vars.setdefault(var, False)
        else:
            scope.vars[var] = rhs_tainted


def _expr_tainted(expr, scopes, source_re):
    if source_re.search(expr):
        return True
    for token in VAR_TOKEN.findall(expr):
        if _lookup(scopes, token):
            return True
    return False


def _lookup(scopes, var):
    if scopes[-1].vars.get(var):
        return True
    if var in scopes[-1].globals and scopes[0].vars.get(var):
        return True
    return False
