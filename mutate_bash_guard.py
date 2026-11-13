#!/usr/bin/env python3
"""Mutation-test bash_guard.py: each mutant removes or bends one rule; the table tests must fail for every one.
A SURVIVED mutant means that rule has no test protecting it. Run: python3 mutate_bash_guard.py"""
import pathlib
import subprocess
import sys
import tempfile

HOOKS = pathlib.Path(__file__).resolve().parent
src = (HOOKS / "bash_guard.py").read_text()
mutants = {
    "aws non-read ops allowed": ('    ask.append(f"`aws {service} {op}` against the PROD account")', "    pass"),
    "Bash write guard removed": ("def check_writes(targets, raw, deny):\n", "def check_writes(targets, raw, deny):\n    return\n"),
    "gh release gate removed": ('"delete-asset"):\n        ask.append', '"delete-asset"):\n        pass  # ask.append'),
    "git force gate removed": ("        if force:\n            ask.append", "        if False:\n            ask.append"),
    "prod write gate removed": ("            elif WRITE_CODE.search(code):", "            elif False:"),
    "read-only exemption removed": ("            elif WRITE_CODE.search(code):", "            elif True:"),
    "heredoc code invisible": ("            return bodies[int(h.group(1))]", "            return None"),
    "script files invisible": ("def read_small(path):\n", "def read_small(path):\n    return None\n"),
    "inline AWS_PROFILE leaks to later cmds": ("        scoped = {**env, **assigns}\n", "        scoped = {**env, **assigns}\n        env.update(assigns)\n"),
    "any mention = prod (the 09-29 bug)": ("PROD_CREDENTIAL = re.compile(\n", "PROD_CREDENTIAL = re.compile(PROD_ACCOUNT) or re.compile(\n"),
    "explicit dev profile doesn't win": ('        return "prod" if PROD_ACCOUNT in prof else "nonprod"', '        return "prod" if PROD_ACCOUNT in prof else None'),
    "explicit dev stage doesn't win": ('        return "prod" if stage.lower() in PROD_STAGES else "nonprod"', '        return "prod" if stage.lower() in PROD_STAGES else None'),
    "sourced prod env ignored": ('                env["AWS_PROFILE"] = PROD_ACCOUNT', "                pass"),
    "continuation lines not joined": (r'expand_ansi_c(cmd.replace("\\\n", ""))', "expand_ansi_c(cmd)"),
    "continuation joined with a space": (r'cmd.replace("\\\n", "")', r'cmd.replace("\\\n", " ")'),
    "<( parsed as a redirect": ('        if tok in ("<(", ">(") or (is_op(tok)', "        if (is_op(tok)"),
    "stacks-map mention = write": ("    if FORCE_TRUE.search(cmd) and writes_stacks_map(cmd):", '    if FORCE_TRUE.search(cmd) and "stacks-map.js" in cmd:'),
    "substitutions not extracted": ("        text, subs = extract_substitutions(text)\n", "        subs = []\n"),
    "debris names treated as programs": ("        return None, [], assigns  # `$G`", "        pass  # `$G"),
    "deploy heuristic reads code strings": ('\n                 and a is not code_arg and not re.search(r"\\s", a)), "")', '), "")'),
    "function calls not expanded": ("                queue[i + 1:i + 1] = [list(s) for s in funcs[name]]", "                pass"),
    "name() definitions not recognized": ('        if tok == "()" and (len(cur) == 1', '        if False and (len(cur) == 1'),
    "function-keyword form not split": ('        if len(seg) >= 3 and seg[0] == "function"', '        if False and seg[0] == "function"'),
    "dry-run exemption too loose": ('    if name not in ("node", "python", "python3") or "--apply" in args:\n        return False', "    return True"),
    "web main push gate removed": ('            if "main" in dests:', "            if False:"),
    "heredoc bodies parsed as code": ("def strip_heredocs(cmd):\n", "def strip_heredocs(cmd):\n    return cmd, []\n"),
    "every-merge gate removed": ("        else:\n            ask.append(f\"`gh pr merge` into {target", "        elif False:\n            ask.append(f\"`gh pr merge` into {target"),
    "nested shells not analyzed": ("if name in SHELLS else None)", "if False else None)"),
    "eval not analyzed": ('nested = " ".join(args) if name == "eval" else (', 'nested = None if name == "eval" else ('),
    "nesting depth unbounded": ("                elif depth < 3:\n", "                elif True:\n"),
    "nested shell skips the outer checks": ("                    ask += inner_ask\n", "                    ask += inner_ask\n                    continue\n"),
    "eval text not treated as visible code": ("            code = nested if nested is not None else (", "            code = ("),
    "shell options read as code flags": ("written, name in SHELLS) if INTERPRETER", "written) if INTERPRETER"),
    "real comments not stripped": ("def strip_comments(s):\n", "def strip_comments(s):\n    return s\n"),
    "comment runs past the newline": ('            j = s.find("\\n", i)\n', "            j = -1\n"),
    "mid-word # treated as comment": ('    lex.commenters = ""', '    lex.commenters = "#"'),
    "AWS_DEFAULT_PROFILE ignored (aws)": ('check_aws(args, scoped.get("AWS_PROFILE") or scoped.get("AWS_DEFAULT_PROFILE"), ask)', 'check_aws(args, scoped.get("AWS_PROFILE"), ask)'),
    "AWS_DEFAULT_PROFILE ignored (code)": ('    prof = scoped.get("AWS_PROFILE") or scoped.get("AWS_DEFAULT_PROFILE")\n', '    prof = scoped.get("AWS_PROFILE")\n'),
    "sls stage case-sensitive": ("    prod = stage.lower() in PROD_STAGES", "    prod = stage in PROD_STAGES"),
    "parse errors fail open": ('        ask.append("command could not be parsed, so the guard can\'t check it")\n', "        pass\n"),
    "shell option clusters ignored": ('has_c = has_c or (a[0] == "-" and "c" in a)', 'has_c = has_c or a == "-c"'),
    "-o argument read as the code": ('i += 2 if a[-1] in "oO" else 1', "i += 1"),
    "$'...' strings not read": ("def expand_ansi_c(s):\n", "def expand_ansi_c(s):\n    return s\n"),
    "$'...' escapes not decoded": ("ANSI_C_ESCAPE.sub(_ansi_c_char, s[i + 2:j])", "s[i + 2:j]"),
    "$'...' kept past NUL": (r'.split("\x00", 1)[0]', ""),
    "substitution bodies not normalized": ("segments(normalize(sub))", "segments(sub)"),
    "unseen command names allowed": ("        if name == UNSEEN:\n", "        if False:\n"),
    "command words not expanded": ("    word = expand_vars(words[i], env) if env else words[i]\n", "    word = words[i]\n"),
    "expanded command line not word-split": (r'    if word != words[i] and re.search(r"\s", word):', "    if False:"),
    "prefix-assigned variable read": (r'if set(re.findall(r"\$\{?([A-Za-z_]\w*)", nested)) & set(assigns):', "if False:"),
    'substitution output seen as a command': ('"__SUBST__" in word or ', ''),
    'nested env not inherited': ('depth + 1, scoped, sure if', 'depth + 1, None, sure if'),
    'certainty not inherited by nested lines': ('sure if name == "eval" else sure & exported, dirs)', 'frozenset(), dirs)'),
    'IFS ignored': ('re.search(r"(?<![\\w$])IFS\\+?=", text) or DYNAMIC_BINDING', 'DYNAMIC_BINDING'),
    'other bindings ignored': ('if re.search(r"(?<![\\w${])" + name + r"(?![\\w=}])", text):', 'if False:'),
    'repeated assignments trusted': ('len(found) == 1', 'len(found) >= 1'),
    'conditional assignment trusted': (' and not CONTROL_BEFORE.search(text[:found[0].start()])', ''),
    'directory part not checked': ('or "$" in seen:', 'or "$" in word.rsplit("/", 1)[-1]:'),
    'standard directory variables not allowed': ('    seen = re.sub(', '    seen = word or re.sub('),
    'dynamic bindings ignored': ('IFS\\+?=", text) or DYNAMIC_BINDING.search(text):', 'IFS\\+?=", text):'),
    'piped assignment trusted': ('    if re.search(r"[|&(]", text):', '    if False:'),
    'assigned safe directory trusted': ('if not re.search(r"(?<![\\w${])" + v + r"(?![\\w}])", text)', 'if True'),
    'dynamic binding keeps safe directories': ('    if DYNAMIC_BINDING.search(text):\n        return frozenset()\n', ''),
    'child shells see unexported variables': ('sure if name == "eval" else sure & exported', 'sure'),
    'export not tracked': ('            exported.update(a.split("=", 1)[0] for a in args if not a.startswith("-"))\n', ''),
    'binding words matched inside paths': ('r"|getopts|let|unset)(?=\\s|$)', 'r"|getopts|let|unset)'),
    'printf option clusters missed': ('r"\\bprintf\\b[^;&|\\n]*\\s-\\w*v|', 'r"\\bprintf\\s+-v(?=\\s)|'),
}
scratch = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp(prefix="bash-guard-mutants-"))
survivors = 0
for name, (old, new) in mutants.items():
    assert src.count(old) == 1, f"mutation anchor not unique/found: {name}"
    p = scratch / "mutant_bash_guard.py"
    p.write_text(src.replace(old, new))
    r = subprocess.run([sys.executable, str(HOOKS / "test_bash_guard.py"), str(p)], capture_output=True, text=True)
    killed = r.returncode != 0
    survivors += not killed
    print(f"{'KILLED ' if killed else 'SURVIVED'}  {name:40s} {r.stdout.strip().splitlines()[-1]}")
sys.exit(1 if survivors else 0)
