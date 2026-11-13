#!/usr/bin/env python3
"""PreToolUse(Bash) guard for Claude Code. Called by bash-guard.sh; tests: test_bash_guard.py.

Prints a hook decision as JSON on stdout (no output = no opinion):
  deny  Bash writes to files that Edit/Write guards would protect (secrets, lock files, a serverless-appsync
        stacks-map `force: true`), so `sed -i`, redirects and heredoc scripts can't route around those guards.
  ask   Actions that change PROD or rewrite shared history: non-read AWS calls and scripts against the prod
        account, prod `sls deploy|remove|rollback|invoke`, prod deploy scripts, `gh release
        create|delete|edit|upload`, prod workflow dispatch/rerun, every `gh pr merge` (when GitHub enforces no
        review or required check, the human's go is the review), pushes into the protected repo's main,
        force/delete pushes, `--no-verify`.

Configuration (environment): BASH_GUARD_PROD_ACCOUNT  the 12-digit prod AWS account id your profiles contain;
BASH_GUARD_PROTECTED_REPO  a repo whose `main` deploys to prod (pushes and merges into it always ask);
BASH_GUARD_OFFLINE=1  never call `gh` (used by the tests).

Prod READS (describe/get/list/query/scan/logs...) are deliberately not gated.
A segment is "prod" when its own command line or environment selects prod credentials (AWS_PROFILE, --profile /
--aws-profile, --stage prod, a sourced env file switching to prod) — an explicit non-prod profile or stage wins —
or, with nothing selected, when the code it runs picks the prod profile itself. For an interpreter (python, node,
bash…) whose code is visible (-c/-e, heredoc, a script written earlier in the command, the script file on disk),
only code that touches AWS with a WRITE call is gated; prod-read code passes. Invisible code under prod
credentials still asks. A bare mention of the account id (an ARN, a CDK account map, docs) is data, not use.
Nested shells (`bash -c`, `bash -lc`, a heredoc'd or script-file shell) and `eval` are re-checked as command
lines with the same rules, and one it can't see asks. Comments, backslash-newlines and `$'...'` strings are read
the way bash reads them, and a command that can't be parsed asks.
Lessons that shaped it: matching on any mention of the account id prompted on `mkdir` and CDK edits; scanning
on-disk scripts that merely SUPPORT prod flagged `ruff`, `cmp` and `--stage dev` runs; continuation lines and
`<(…)` were mis-parsed. A hook "ask" prompts even in auto mode and even when an allow rule like Bash(gh *)
matches, because allow rules are resolved before the auto-mode classifier.
"""
import json
import os
import re
import shlex
import subprocess
import sys

PROD_ACCOUNT = os.environ.get("BASH_GUARD_PROD_ACCOUNT", "111111111111")
# Credential SELECTION of the prod account (profile_name=…, AWS_PROFILE=…, --profile …, fromIni({profile: …})).
PROD_CREDENTIAL = re.compile(
    r"(?:profile_name|profile|AWS_PROFILE|AWS_DEFAULT_PROFILE|--profile|--aws-profile)[\"'\]\s]*[:=,]?\s*[\"']?[^\"'\s,)]*" + PROD_ACCOUNT)
HEREDOC_TOKEN = re.compile(r"__HEREDOC_(\d+)__")
INTERPRETER = re.compile(r"^(python[\d.]*|node|bash|sh|zsh|ruby|perl|deno|bun|tsx|ts-node)$")
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}  # their -c string / heredoc / script is re-checked as a command line
UNSEEN = "$unseen"  # command_of's name for a command word the guard can't resolve: `$CMD`, `"$@"`, `$(…)` output
# Code that CHANGES state (boto3 snake_case verbs, SDK v3 *Command classes, DocumentClient v2,
# CLI write ops, HTTP writes). add_/import_/set_ are left out on purpose: argparse add_argument, importlib
# import_module etc. are everywhere and never write to AWS.
WRITE_CODE = re.compile(
    r"\b(?:put|update|delete|create|batch_write|transact_write|send|start|stop|terminate|reboot|modify|restore"
    r"|attach|detach|tag|untag|upload|copy|execute_statement|batch_execute_statement|rotate|enable|disable"
    r"|register|deregister|associate|disassociate|cancel|reset|remove)_\w*\s*\(|\b(?:invoke|publish)\s*\("
    r"|\bset_(?:alarm_state|\w*_attributes)\s*\("
    r"|\b(?:Put|Update|Delete|Create|BatchWrite|TransactWrite|Invoke|Start|Stop|Send|Publish|Attach|Detach|Tag"
    r"|Untag|Remove|Modify|Restore|Reset|Terminate|Upload|Copy|Import|Rotate|Enable|Disable|Register|Deregister"
    r"|Execute|Set)\w*Command\b"
    r"|\.(?:putItem|updateItem|deleteItem|batchWrite\w*|transactWrite\w*)\s*\(|\.(?:put|update|delete)\(\s*\{\s*[\"']?TableName"
    r"|\baws\s+[a-z0-9-]+\s+(?!(?:describe|get|list|lookup|search|filter|batch-get|head|query|scan|tail|wait|ls|help)"
    r"[a-z-]*\b)[a-z]+-[a-z-]+|\baws\s+s3\s+(?:cp|mv|rm|sync|mb|rb)\b"
    r"|\brequests\.(?:post|put|patch|delete)\s*\(")
WEB_REPO = os.environ.get("BASH_GUARD_PROTECTED_REPO", "web_app")  # main deploys to PROD
OFFLINE = os.environ.get("BASH_GUARD_OFFLINE") == "1"  # tests: never call gh

AWS_READ_OP = re.compile(
    r"^(describe|get|list|lookup|search|filter|batch-get|head|query|scan|tail|wait|ls|validate|simulate"
    r"|presign|start-query|start-live-tail|stop-query|help)"
)
AWS_FLAG_ONLY = {"--debug", "--no-verify-ssl", "--no-paginate", "--no-cli-pager", "--no-sign-request",
                 "--no-cli-auto-prompt", "--cli-auto-prompt"}
SLS_MUTATING = {"deploy", "remove", "rollback", "invoke"}
PROD_STAGES = {"prod", "production"}

# Local-only tools: they can't reach AWS, whatever their arguments say.
LOCAL_TOOLS = {"jq", "grep", "egrep", "fgrep", "rg", "head", "tail", "sort", "uniq", "wc", "awk", "cut", "tr",
               "column", "cat", "echo", "printf", "true", "false", "test", "[", "date", "sleep", "less", "diff",
               "comm", "paste", "nl", "base64", "shasum", "md5", "tee", "sed", "ls", "find", "stat", "basename",
               "dirname", "realpath", "which", "type", "open", "pbcopy", "mkdir", "touch", "cp", "mv", "rm",
               "rmdir", "ln", "chmod", "chown", "tar", "zip", "unzip", "gzip", "gunzip", "cmp", "ruff", "black",
               "isort", "mypy", "flake8", "pylint", "pyright", "eslint", "prettier", "tsc", "shellcheck", "curl", "wget", "http", "dig",
               "nslookup", "host", "openssl", "nc", "ping"}
BUILTINS = {"cd", "pushd", "popd", "export", "set", "unset", "local", "read", "shift", "return", "exit",
            "break", "continue", "declare", "typeset", "trap", "umask", "readonly", "let", "wait"}
SKIP_WORDS = {"do", "then", "else", "elif", "!", "time", "{", "if", "while", "until"}
BENIGN_SEGMENT_START = {"for", "case", "select", "function", "done", "fi", "esac", "}", "in"}
WRAPPERS = {"env", "sudo", "nohup", "exec", "timeout", "caffeinate", "command", "builtin", "xargs"}
RUNNERS = {"npx", "pnpx", "bunx", "uvx"}

SECRET_FILE = re.compile(r"(\.env\.(development|local|secret)$|key\.properties$|\.(pem|p12|keystore|jks)$|/certs/)")
LOCK_FILE = re.compile(r"(^|/)(package-lock\.json|pubspec\.lock|poetry\.lock|yarn\.lock|pnpm-lock\.yaml"
                       r"|Podfile\.lock|uv\.lock|Gemfile\.lock)$")
FORCE_TRUE = re.compile(r"force\s*:\s*true")
HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
FUNC_NAME = re.compile(r"[A-Za-z_][\w.-]*")
GH_VALUE_OPTS = {"-R", "--repo", "-X", "--method", "-H", "--header", "-q", "--jq", "-t", "--template",
                 "--json", "-b", "--body", "-F", "--field", "-f", "--raw-field", "--input", "--subject",
                 "--match-head-commit", "-A", "--author", "--ref", "-r", "--title", "-n", "--notes",
                 "--notes-file", "--target", "--discussion-category"}


def strip_heredocs(cmd):
    """Split heredoc bodies out (their quotes/apostrophes would break tokenizing). Each body is replaced by a
    `__HEREDOC_<n>__` word on its opening line, so the segment that consumes it stays attributable.
    Returns (text, bodies)."""
    out, pending, bodies = [], [], []
    for line in cmd.split("\n"):
        if pending:
            if line.strip() == pending[0][0]:
                pending.pop(0)
            else:
                bodies[pending[0][1]].append(line)
            continue
        marks = []
        for m in HEREDOC.finditer(line):
            if m.start() > 0 and line[m.start() - 1] == "<":  # <<< here-string, not a heredoc
                continue
            pending.append((m.group(2), len(bodies)))
            marks.append((m.end(), len(bodies)))
            bodies.append([])
        for end, n in reversed(marks):
            line = f"{line[:end]} __HEREDOC_{n}__{line[end:]}"
        out.append(line)
    return "\n".join(out), ["\n".join(b) for b in bodies]


def extract_substitutions(s):
    """Pull `$( … )`, backticks and `$(( … ))` out of a command line the way the shell does: each substitution is
    its own command (returned in `subs`) and leaves a placeholder word in the outer command — so `aws … --start-time
    $(date …) --end-time …` stays ONE aws command instead of being cut at the parentheses."""
    out, subs, i, n, quote = [], [], 0, len(s), None
    while i < n:
        c = s[i]
        if quote == "'":
            out.append(c)
            quote = None if c == "'" else quote
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            out.append(s[i:i + 2])
            i += 2
            continue
        if c in "'\"" and quote is None:
            quote = c
        elif c == '"' and quote == '"':
            quote = None
        if s.startswith("$(", i) or c == "`":
            arith = s.startswith("$((", i)
            if c == "`":
                j = s.find("`", i + 1)
                j, start = (n if j == -1 else j), i + 1
            else:
                depth, j = 0, i + 1
                while j < n:
                    depth += {"(": 1, ")": -1}.get(s[j], 0)
                    if depth == 0:
                        break
                    j += 1
                start = i + 2
            inner, nested = extract_substitutions(s[start:j] if not arith else s[i + 3:max(i + 3, j - 1)])
            if not arith:
                subs.append(inner)
            subs.extend(nested)
            out.append("__SUBST__")  # part of the word it sits in: S=$(…) stays an assignment
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out), subs


def strip_comments(s):
    """Drop shell comments the way bash does: `#` starts one only at the start of a word (after whitespace, a
    newline or an operator) and outside quotes. shlex's own comment handling also cuts `a#b` mid-word, which
    would hide everything after it from the guard."""
    out, i, n, quote = [], 0, len(s), None
    while i < n:
        c = s[i]
        if quote:
            out.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                out.append(s[i + 1])
                i += 2
                continue
            quote = None if c == quote else quote
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            out.append(s[i:i + 2])
            i += 2
            continue
        if c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or s[i - 1] in " \t\n;&|()<>"):
            j = s.find("\n", i)
            i = n if j == -1 else j
            continue
        out.append(c)
        i += 1
    return "".join(out)


ANSI_C_ESCAPE = re.compile(r"\\(?:x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{1,4})|U([0-9A-Fa-f]{1,8})|([0-7]{1,3})|c(.)|(.))", re.S)
ANSI_C_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v",
                 "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _ansi_c_char(m):
    hx, u, big_u, octal, ctrl, other = m.groups()
    if hx or u or big_u:
        cp = int(hx or u or big_u, 16)
        return chr(cp) if cp <= 0x10FFFF else ""
    if octal:
        return chr(int(octal, 8) & 0xFF)
    if ctrl is not None:
        return chr(ord(ctrl) & 0x1F)
    return ANSI_C_SIMPLE.get(other, "\\" + other)


def expand_ansi_c(s):
    """Rewrite each $'...' string (bash's ANSI-C quoting) as a plain single-quoted one. Inside $'...' a backslash
    escapes the next character, so \\' does not end the string. shlex and strip_comments don't know the form, and
    would read `$'\\' #'; git push` as ending in a comment, though bash runs the push."""
    out, i, n, quote = [], 0, len(s), None
    while i < n:
        c = s[i]
        if quote:
            out.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                out.append(s[i + 1])
                i += 2
                continue
            quote = None if c == quote else quote
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            out.append(s[i:i + 2])
            i += 2
            continue
        if c == "$" and s.startswith("'", i + 1):
            j = i + 2
            while j < n and s[j] != "'":
                j += 2 if s[j] == "\\" else 1
            if j >= n:  # unterminated: leave it for shlex to reject, so the guard fails closed
                out.append(s[i:])
                break
            text = ANSI_C_ESCAPE.sub(_ansi_c_char, s[i + 2:j]).split("\x00", 1)[0]  # bash ends the string at NUL
            out.append(shlex.quote(text))
            i = j + 1
            continue
        if c in "'\"":
            quote = c
        out.append(c)
        i += 1
    return "".join(out)


def normalize(cmd):
    """What bash does to a command line before it splits words: a backslash-newline is deleted (not turned into a
    space, so `a\\<newline>#b` is one word), $'...' strings are read, and comments are dropped."""
    return strip_comments(expand_ansi_c(cmd.replace("\\\n", "")))


def is_op(tok):
    return tok != "" and all(c in ";&|()<>\n" for c in tok)


def segments(cmd):
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()<>\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""  # bash comments start only at a word boundary: strip_comments handles them
    segs, cur = [], []
    for tok in lex:
        # `name() {` / `function name() {` defines a shell function: mark it, so its body is checked where it's CALLED
        if tok == "()" and (len(cur) == 1 or (len(cur) == 2 and cur[0] == "function")) and FUNC_NAME.fullmatch(cur[-1]):
            segs.append(["__FUNCDEF__", cur[-1]])
            cur = []
            continue
        # `<(…)` / `>(…)` process substitution opens a new command, it is not a redirection
        if tok in ("<(", ">(") or (is_op(tok) and "<" not in tok and ">" not in tok):
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(tok)
    if cur:
        segs.append(cur)
    out = []
    for seg in segs:  # `function name { …` (no parens) arrives as one segment: split the header from the body
        if len(seg) >= 3 and seg[0] == "function" and FUNC_NAME.fullmatch(seg[1]) and seg[2] == "{":
            out += [["__FUNCDEF__", seg[1]], seg[2:]]
        else:
            out.append(seg)
    return out


def take_function_body(queue, i):
    """queue[i] is a __FUNCDEF__ marker: return the index just past the `{ … }` body that follows it (i + 1 if none)."""
    j, depth = i + 1, 0
    while j < len(queue):
        depth += queue[j].count("{") - queue[j].count("}")
        j += 1
        if depth <= 0:
            break
    return j if depth <= 0 and j > i + 1 and queue[i + 1][:1] == ["{"] else i + 1


def split_redirects(seg):
    """Return (words without redirections, redirection targets)."""
    words, targets, i = [], [], 0
    while i < len(seg):
        t = seg[i]
        if is_op(t) and ">" in t:
            if i + 1 < len(seg) and not re.fullmatch(r"&?\d+|-", seg[i + 1]):
                targets.append(seg[i + 1])
            i += 2
            continue
        if is_op(t) and "<" in t:
            i += 2
            continue
        words.append(t)
        i += 1
    return words, targets


CONTROL_BEFORE = re.compile(r"&&|\|\||[|({]|\b(?:if|then|else|elif|do|while|until|case|for|select|function)\b")
SAFE_DIR_VAR = re.compile(r"^\$\{?(?:HOME|PWD|TMPDIR|CLAUDE_PROJECT_DIR)\}?(?=/)")  # "$HOME/.local/bin/ruff"


def certain_vars(text, inherited=frozenset()):
    """Variables whose value is certain where a later command word reads it: assigned exactly once in this command
    line, with no &&, ||, pipe, group or control keyword before that assignment (it may not run), and never bound
    another way (read, printf -v, for, declare). Only bare and exported assignments reach env. Inherited names stay
    certain unless this line binds them again. Nothing is certain once IFS is assigned: word splitting changes."""
    if re.search(r"(?<![\w$])IFS\+?=", text):
        return set()
    sure = set()
    for name in set(inherited) | set(re.findall(r"(?<![\w$])([A-Za-z_]\w*)\+?=", text)):
        if re.search(r"(?<![\w${])" + name + r"(?![\w=}])", text):  # read NAME, printf -v NAME, for NAME in …
            continue
        found = list(re.finditer(r"(?<![\w$])" + name + r"\+?=", text))
        if not found or (len(found) == 1 and not CONTROL_BEFORE.search(text[:found[0].start()])):
            sure.add(name)
    return sure


def command_of(words, env=None):
    """Return (command name, args, inline assignments); name is None for keyword-only segments and UNSEEN for a
    command word made of a variable or a substitution that this command line didn't set (`$CMD`, `$(echo git)`).
    A variable whose value is certain (env holds only those: see certain_vars) is expanded, and an unquoted one
    holding a whole command line is word-split into it, as bash does."""
    assigns, i = {}, 0
    while i < len(words):
        t = words[i]
        if ASSIGN.match(t):
            k, v = t.split("=", 1)
            assigns[k] = v
            i += 1
            continue
        if t in SKIP_WORDS:
            i += 1
            continue
        if t in BENIGN_SEGMENT_START:
            return None, [], assigns
        base = t.rsplit("/", 1)[-1]
        if base in WRAPPERS or base in RUNNERS:
            i += 1
            while i < len(words) and words[i].startswith("-"):
                i += 1
            if base == "timeout" and i < len(words):
                i += 1
            continue
        if base == "pipx" and i + 1 < len(words) and words[i + 1] == "run":
            i += 2
            continue
        break
    if i >= len(words):
        return None, [], assigns
    word = expand_vars(words[i], env) if env else words[i]
    if word != words[i] and re.search(r"\s", word):  # `CMD="git push --force"; $CMD`
        return command_of(words[:i] + word.split() + words[i + 1:])
    if "__SUBST__" in word or "$" in SAFE_DIR_VAR.sub("", word):  # `$X/grep`, `$(…)/git`: the whole word must be seen
        return UNSEEN, words[i + 1:], assigns
    name = word.rsplit("/", 1)[-1]
    if not re.fullmatch(r"[A-Za-z0-9_.][\w.+-]*", name) or not re.search(r"[A-Za-z]", name):
        return None, [], assigns  # `$G`, `-`, `*`, `000`, `--end-time`: debris, not a command
    return name, words[i + 1:], assigns


def resolve(base, p):
    p = os.path.expanduser(p)
    return os.path.normpath(p if os.path.isabs(p) else os.path.join(base, p))


def run(args, cwd):
    try:
        r = subprocess.run(args, cwd=cwd if os.path.isdir(cwd) else None, capture_output=True, text=True,
                           timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def repo_name(d):
    url = run(["git", "-C", d, "remote", "get-url", "origin"], d)
    if not url:
        return None
    name = url.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    return name[:-4] if name.endswith(".git") else name


def current_branch(d):
    return run(["git", "-C", d, "rev-parse", "--abbrev-ref", "HEAD"], d)


def gh_lookup(args, repo, cwd):
    if OFFLINE:
        return None
    return run(["gh", *args, *(["-R", repo] if repo else [])], cwd)


def positionals(args, value_opts=None):
    value_opts = value_opts or set()
    pos, flags, values, i = [], [], {}, 0
    while i < len(args):
        t = args[i]
        if t.startswith("-") and t != "-":
            key = t.split("=", 1)[0]
            flags.append(key)
            if "=" in t:
                values[key] = t.split("=", 1)[1]
            elif key in value_opts and i + 1 < len(args):
                values[key] = args[i + 1]
                i += 1
            i += 1
            continue
        pos.append(t)
        i += 1
    return pos, flags, values


def check_aws(args, profile_env, ask):
    explicit, pos, i = None, [], 0
    while i < len(args):
        t = args[i]
        if t.startswith("--"):
            key = t.split("=", 1)[0]
            if key == "--profile":
                explicit = t.split("=", 1)[1] if "=" in t else (args[i + 1] if i + 1 < len(args) else "")
                i += 1 if "=" in t else 2
                continue
            if t in AWS_FLAG_ONLY or "=" in t or len(pos) >= 2:
                i += 1
                continue
            i += 2  # global option with a value, before the service/operation
            continue
        pos.append(t)
        i += 1
    is_prod = PROD_ACCOUNT in (explicit if explicit is not None else (profile_env or ""))
    if not is_prod or not pos:
        return
    service, op = pos[0], (pos[1] if len(pos) > 1 else "")
    if service == "s3":
        if op in ("ls", "presign") or (op in ("cp", "sync") and not pos[-1].startswith("s3://")):
            return
    elif AWS_READ_OP.match(op) or service == "help":
        return
    ask.append(f"`aws {service} {op}` against the PROD account")


def check_sls(args, env, seg_prod, ask):
    pos, _, values = positionals(args, {"--stage", "-s", "--aws-profile", "--function", "-f", "--region",
                                             "-r", "--config", "-c", "--param", "--data", "-d", "--path", "-p"})
    verb = pos[0] if pos else ""
    if verb not in SLS_MUTATING or (verb == "invoke" and len(pos) > 1 and pos[1] == "local"):
        return
    stage = values.get("--stage") or values.get("-s") or env.get("STAGE") or ""
    prod = stage.lower() in PROD_STAGES or env.get("ENV", "").endswith("-prod") or seg_prod
    if prod:
        ask.append(f"`sls {verb}` targeting PROD (stage {stage or env.get('ENV') or 'prod account'})")


def check_gh(args, cur_dir, ask):
    pos, flags, values = positionals(args, GH_VALUE_OPTS)
    repo = values.get("-R") or values.get("--repo")
    if pos[:1] == ["release"] and len(pos) > 1 and pos[1] in ("create", "delete", "edit", "upload",
                                                                "delete-asset"):
        ask.append(f"`gh release {pos[1]}` — releases trigger a PROD deploy")
    elif pos[:2] == ["workflow", "run"]:
        wf = pos[2] if len(pos) > 2 else ""
        if not wf or wf.isdigit() or "prod" in wf.lower():
            ask.append(f"`gh workflow run {wf or '(picker)'}` — dispatches a PROD deploy workflow")
    elif pos[:2] == ["run", "rerun"]:
        rid = pos[2] if len(pos) > 2 else ""
        name = gh_lookup(["run", "view", rid, "--json", "workflowName", "-q", ".workflowName"], repo,
                         cur_dir) if rid else None
        if name is None or "prod" in name.lower():
            ask.append(f"`gh run rerun {rid}` — workflow {name or 'unknown'} may be a PROD deploy")
    elif pos[:2] == ["pr", "merge"]:
        if "--admin" in flags:
            ask.append("`gh pr merge --admin` bypasses branch protection")
            return
        # Always asks: branch protection and rulesets are unavailable on the free plan (API 403, measured
        # 2026-10-17), so nothing else stops a merge with a red check. The lookup only informs the prompt.
        target = (repo or repo_name(cur_dir) or "").rsplit("/", 1)[-1]
        info = gh_lookup(["pr", "view", *pos[2:3], "--json", "baseRefName,mergeStateStatus", "-q",
                          '.baseRefName + " " + .mergeStateStatus'], repo, cur_dir)
        base, state = info.split(" ", 1) if info and " " in info else (None, None)
        if target == WEB_REPO and base in (None, "main"):
            ask.append(f"`gh pr merge` into {WEB_REPO} {base or '(base unknown)'} — its main deploys "
                       "to PROD")
        else:
            ask.append(f"`gh pr merge` into {target or 'this repo'} {base or '(base unknown)'}: GitHub enforces "
                       f"no review or required check here, so this prompt is the review. Merge state "
                       f"{state or 'unknown'} (CLEAN = all checks green; UNSTABLE = a check failed or is pending)")
    elif pos[:1] == ["api"]:
        path = pos[1] if len(pos) > 1 else ""
        method = (values.get("-X") or values.get("--method") or "").upper()
        writes = method in ("POST", "PUT", "PATCH", "DELETE") or any(
            f in flags for f in ("-f", "-F", "--field", "--raw-field", "--input"))
        if writes and re.search(r"/(releases|dispatches|merges?)\b|/git/refs", path):
            ask.append(f"`gh api {method or 'POST'} {path}` — release/dispatch/merge endpoint")


def dest_of(refspec, d):
    dst = refspec.lstrip("+")
    dst = dst.split(":", 1)[1] if ":" in dst else dst
    if dst in ("HEAD", "@", ""):
        dst = current_branch(d) or ""
    return dst[len("refs/heads/"):] if dst.startswith("refs/heads/") else dst


def check_git(args, cur_dir, ask):
    d, i = cur_dir, 0
    while i < len(args):
        t = args[i]
        if t == "-C" and i + 1 < len(args):
            d = resolve(d, args[i + 1])
            i += 2
            continue
        if t in ("-c", "--git-dir", "--work-tree", "--namespace") and i + 1 < len(args):
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        break
    if i >= len(args):
        return
    sub, rest = args[i], args[i + 1:]
    shorts = [a for a in rest if re.fullmatch(r"-[A-Za-z]+", a)]
    if sub == "push":
        pos, flags, _ = positionals(rest, {"-o", "--push-option", "--repo", "--receive-pack", "--exec"})
        force = (any(f in ("--force", "--mirror", "--delete", "--prune", "--force-if-includes")
                     or f.startswith("--force-with-lease") for f in flags)
                 or any("f" in s or "d" in s for s in shorts)
                 or any(p.startswith(("+", ":")) for p in pos[1:]))
        if force:
            ask.append("`git push` with force/delete rewrites or deletes remote history")
        if "--no-verify" in flags:
            ask.append("`git push --no-verify` skips hooks")
        if repo_name(d) == WEB_REPO:
            dests = [dest_of(r, d) for r in pos[1:]] or [current_branch(d) or ""]
            if "main" in dests:
                ask.append(f"push to {WEB_REPO} main = PROD deploy (push to a non-main branch instead)")
    elif sub == "commit":
        if "--no-verify" in rest or any("n" in s for s in shorts):
            ask.append("`git commit --no-verify` skips hooks")


def write_targets(name, args, redirects):
    targets = list(redirects)
    plain = [a for a in args if not a.startswith("-")]
    if name == "tee":
        targets += plain
    elif name in ("sed", "gsed") and any(a.startswith("-i") or a == "--in-place" for a in args):
        targets += plain
    elif name == "perl" and any(re.fullmatch(r"-[A-Za-z]*i\S*", a) for a in args):
        targets += plain
    elif name in ("cp", "mv", "install", "ln", "rsync") and plain:
        targets.append(plain[-1])
    elif name == "truncate":
        targets += plain
    elif name == "dd":
        targets += [a[3:] for a in args if a.startswith("of=")]
    return targets


def check_writes(targets, raw, deny):
    for t in targets:
        if SECRET_FILE.search(t):
            deny.append(f"BLOCK: {t} looks like a secrets/credential file. Do not write it with Claude (Bash "
                        "writes are guarded like Edit/Write) — ask the user to change it manually.")
        elif LOCK_FILE.search(t):
            deny.append(f"BLOCK: {t} is a lock file — run the package manager instead of writing it directly.")
        elif t.endswith("stacks-map.js") and FORCE_TRUE.search(raw):
            deny.append("BLOCK: never add force: true in stacks-map.js — it makes serverless-appsync-plugin "
                        "recreate AppSync resolvers instead of updating them.")


def is_dry_run_script(name, args, cur_dir):
    """Prod script runs pass only when the script implements an `--apply` switch (dry run by default) and it's absent."""
    if name not in ("node", "python", "python3") or "--apply" in args:
        return False
    script = next((a for a in args if not a.startswith("-")), None)
    if not script or "scripts/" not in script:
        return False
    try:
        with open(resolve(cur_dir, script), encoding="utf-8", errors="ignore") as fh:
            return "--apply" in fh.read()
    except OSError:
        return False


def read_small(path):
    try:
        if os.path.isfile(path) and os.path.getsize(path) <= 2_000_000:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                return fh.read()
    except OSError:
        pass
    return None


def prod_selection(scoped, args):
    """'prod' / 'nonprod' / None: the credentials this segment's own command line or environment selects —
    --profile / --aws-profile, then AWS_PROFILE, then --stage. An explicit choice beats code-level hints."""
    prof = scoped.get("AWS_PROFILE") or scoped.get("AWS_DEFAULT_PROFILE")
    for i, a in enumerate(args):
        if a in ("--profile", "--aws-profile") and i + 1 < len(args):
            prof = args[i + 1]
        elif a.startswith(("--profile=", "--aws-profile=")):
            prof = a.split("=", 1)[1]
    if prof:
        return "prod" if PROD_ACCOUNT in prof else "nonprod"
    stage = next((args[i + 1] for i, a in enumerate(args[:-1]) if a == "--stage"), None) or next(
        (a.split("=", 1)[1] for a in args if a.startswith("--stage=")), None)
    if stage:
        return "prod" if stage.lower() in PROD_STAGES else "nonprod"
    return None


def code_index(args, shell):
    """Where a `-c`-style invocation keeps its code, or None. A shell takes it from the first operand after its
    options when any option cluster contains c (`bash -lc 'cmd'`, `sh -ec 'cmd'`, `bash -o pipefail -c 'cmd'`);
    other interpreters from the word after -c / -e / --eval or a cluster ending in c or e (`python3 -Bc`, `perl -ne`)."""
    if shell:
        has_c, i = False, 0
        while i < len(args):
            a = args[i]
            if a == "--":
                i += 1
                break
            if re.fullmatch(r"[-+][A-Za-z]+", a):
                has_c = has_c or (a[0] == "-" and "c" in a)
                i += 2 if a[-1] in "oO" else 1  # -o / -O take an option name
            elif a in ("--rcfile", "--init-file"):
                i += 2
            elif a.startswith("--"):
                i += 1
            else:
                break
        return i if has_c and i < len(args) else None
    return next((i + 1 for i, a in enumerate(args[:-1])
                 if a in ("-c", "-e", "--eval") or re.fullmatch(r"-[A-Za-z]*[ce]", a)), None)


def expand_vars(text, env):
    """Substitute $VAR / ${VAR} that this command line set itself; references it can't resolve stay as written."""
    return re.sub(r"\$(?:\{(\w+)\}|([A-Za-z_]\w*))", lambda m: env.get(m.group(1) or m.group(2), m.group(0)), text)


def visible_code(args, bodies, cur_dir, written, shell=False):
    """The code an interpreter segment will run, when the command shows it: a -c/-e string, a heredoc body, a
    script written earlier in this command, or the script file on disk. None when it can't be seen."""
    idx = code_index(args, shell)
    if idx is not None:
        return args[idx]
    for a in args:
        h = HEREDOC_TOKEN.fullmatch(a)
        if h:
            return bodies[int(h.group(1))]
    script = next((a for a in args if not a.startswith("-")), None)
    if script:
        path = resolve(cur_dir, script)
        return written[path] if path in written else read_small(path)
    return None


def writes_stacks_map(cmd):
    """A script that opens stacks-map.js for WRITING — directly or through a variable holding its path.
    Merely mentioning the file (docs, this guard's own source) is not a write."""
    direct = re.search(r"\b(?:open\s*\(\s*[\"'][^\"']*stacks-map\.js[\"']\s*,\s*[\"'][wa]"
                       r"|writeFile\w*\s*\(\s*[\"'][^\"']*stacks-map\.js)", cmd)
    var = re.search(r"\b(\w+)\s*=\s*[\"'][^\"']*stacks-map\.js[\"']", cmd)
    via_var = var and re.search(rf"\b(?:open\s*\(\s*{var.group(1)}\s*,\s*[\"'][wa]|writeFile\w*\s*\(\s*{var.group(1)}\b"
                                rf"|{var.group(1)}\.write_text\s*\()", cmd)
    return bool(direct or via_var)


def analyze(cmd, cwd, depth=0, env0=None, sure0=frozenset()):
    deny, ask = [], []
    if FORCE_TRUE.search(cmd) and writes_stacks_map(cmd):
        deny.append("BLOCK: a script that writes stacks-map.js with force: true — never add force: true "
                    "in stacks-map.js.")
    try:
        text, bodies = strip_heredocs(cmd)
        text = normalize(text)
        text, subs = extract_substitutions(text)
        segs = segments(text) + [s for sub in subs for s in segments(normalize(sub))]  # each body in its own context
    except ValueError:
        ask.append("command could not be parsed, so the guard can't check it")
        return deny, ask
    cur_dir, env, written = cwd, dict(env0 or {}), {}
    sure = certain_vars(text, sure0)  # the only variables a command word may be resolved from
    queue, funcs, expansions, i = list(segs), {}, 0, -1
    while i + 1 < len(queue):
        i += 1
        seg = queue[i]
        if seg[:1] == ["__FUNCDEF__"]:  # store the body; it runs (and is checked) at each call, with the env of that moment
            end = take_function_body(queue, i)
            funcs[seg[1]] = [list(s) for s in queue[i + 1:end]]
            del queue[i + 1:end]
            continue
        words, redirects = split_redirects(seg)
        name, args, assigns = command_of(words, {k: v for k, v in env.items() if k in sure})
        targets = write_targets(name, args, redirects)
        check_writes(targets, cmd, deny)
        body = next((bodies[int(h.group(1))] for h in map(HEREDOC_TOKEN.fullmatch, words) if h), None)
        if body is not None:  # remember what this segment writes to files, in case a later segment runs it
            written.update((resolve(cur_dir, t), body) for t in targets)
        if name == UNSEEN:
            ask.append("runs a command the guard can't see: its name is a variable or a substitution's output")
            continue
        if name is None:
            env.update(assigns)  # bare `VAR=x;` — conservatively treat it as reaching the commands that follow
            continue
        scoped = {**env, **assigns}
        sel = prod_selection(scoped, args)
        if name in ("cd", "pushd") and args:
            cur_dir = resolve(cur_dir, args[0])
        elif name == "export":
            env.update(a.split("=", 1) for a in args if "=" in a)
        elif name in ("source", "."):
            # a sourced env file that switches this shell to prod makes the commands after it prod
            path = resolve(cur_dir, args[0]) if args else ""
            content = written.get(path) or read_small(path) or ""
            if PROD_CREDENTIAL.search(content) and (
                    any(a.lower() in PROD_STAGES for a in args[1:]) or not re.search(r"\b(if|case)\b", content)):
                env["AWS_PROFILE"] = PROD_ACCOUNT
        elif name == "aws":
            check_aws(args, scoped.get("AWS_PROFILE") or scoped.get("AWS_DEFAULT_PROFILE"), ask)
        elif name in ("sls", "serverless"):
            check_sls(args, scoped, sel == "prod", ask)
        elif name == "gh":
            check_gh(args, cur_dir, ask)
        elif name == "git":
            check_git(args, cur_dir, ask)
        elif name in LOCAL_TOOLS or name in BUILTINS:
            continue
        elif name in funcs:
            if expansions < 25:  # the body runs here; a self-calling function must not loop the guard
                expansions += 1
                queue[i + 1:i + 1] = [list(s) for s in funcs[name]]
            continue
        else:
            nested = " ".join(args) if name == "eval" else (
                visible_code(args, bodies, cur_dir, written, shell=True) if name in SHELLS else None)
            if nested is not None:
                # a nested shell runs its own command line: check it like this one, with this segment's env. The
                # outer checks below still apply to it (a deploy script's name and stage, prod-credential writes).
                # A command word inside it that the guard can't resolve asks (command_of's UNSEEN). A variable that
                # this segment's own prefix sets is ambiguous once quoting is gone: `CMD=x eval "$CMD"` expands the
                # outer $CMD, `CMD=x bash -c '$CMD'` the prefix's. Ask rather than guess.
                if set(re.findall(r"\$\{?([A-Za-z_]\w*)", nested)) & set(assigns):
                    ask.append(f"`{name}` reads a variable that its own prefix assignment sets")
                elif depth < 3:
                    inner_deny, inner_ask = analyze(nested, cur_dir, depth + 1, scoped, sure)
                    deny += inner_deny
                    ask += inner_ask
                else:
                    ask.append(f"`{name}` nests shells too deeply to check")
            code_arg = next((args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-c", "-e", "--eval")), None)
            script = name if "deploy" in name else next(  # inline code and prose aren't script names
                (a.rsplit("/", 1)[-1] for a in args if "deploy" in a and not a.startswith("-")
                 and a is not code_arg and not re.search(r"\s", a)), "")
            if script and ("prod" in script.lower() or any(a.lower() in PROD_STAGES for a in args)):
                ask.append(f"`{script}` looks like a PROD deploy")
                continue
            if sel == "nonprod" or is_dry_run_script(name, args, cur_dir):
                continue
            code = nested if nested is not None else (
                visible_code(args, bodies, cur_dir, written, name in SHELLS) if INTERPRETER.match(name) else None)
            if sel != "prod" and not (code and PROD_CREDENTIAL.search(code)):
                continue
            if code is None:
                ask.append(f"`{name}` runs with PROD credentials and its code isn't visible")
            elif WRITE_CODE.search(code):
                ask.append(f"`{name}` runs code that WRITES to AWS with PROD credentials")
    return deny, ask


def main():
    data = json.load(sys.stdin)
    cmd = (data.get("tool_input") or {}).get("command") or ""
    deny, ask = analyze(cmd, data.get("cwd") or os.getcwd())
    if deny:
        decision, reason = "deny", " | ".join(dict.fromkeys(deny))
    elif ask:
        decision = "ask"
        reason = "PROD / shared-history gate: " + "; ".join(dict.fromkeys(ask))
    else:
        return
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                             "permissionDecisionReason": reason}}))


if __name__ == "__main__":
    main()
