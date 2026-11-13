# claude-code-bash-guard

A `PreToolUse` hook for [Claude Code](https://docs.claude.com/en/docs/claude-code) that stops an AI agent from changing production or rewriting shared history through Bash, while still letting it **read** production freely.

I built it for the AWS backend I run as a solo engineer, where Claude Code agents do most of the hands-on work. It runs on every Bash command those agents issue.

## Why a hook

- **Allow rules and auto mode let commands through.** Once `Bash(gh *)` or `Bash(aws *)` is allowed, or auto mode is on, nothing stops `gh release create` or `aws dynamodb delete-item --profile prod`. A hook's `ask` decision prompts a human even then.
- **Edit/Write guards can be routed around.** If you block Claude from editing `.env` files or lock files, it can still write them with `sed -i`, `>`, `tee` or a heredoc'd Python script. This guard gives Bash the same protection.
- **Blunt pattern matching is unusable.** Asking on every command that mentions `prod` or the account id interrupts constant harmless work: `mkdir`, CDK account maps, `grep`, linting a deploy script. The guard parses the command instead, and only asks when the command would actually act on prod.

## What it decides

| Decision | When |
|---|---|
| **deny** | A Bash write to a secrets or credential file (`.env.local`, `.pem`, `.jks`, `key.properties`, `certs/`), a lock file, or `force: true` into a serverless-appsync `stacks-map.js` |
| **ask** | Non-read AWS calls under prod credentials; prod `sls deploy/remove/rollback/invoke`; prod deploy scripts; `gh release create/delete/edit/upload`; prod workflow dispatch or rerun; every `gh pr merge`; pushes into the protected repo's `main`; force or delete pushes; `--no-verify`; a command it can't parse, or a nested command line it can't see |
| **allow** (no output) | Everything else, **including prod reads**: `describe`, `get`, `list`, `query`, `scan`, `logs tail`, `s3 cp` downloads, read-only scripts |

### How it knows a command is "prod"

A command counts as prod when **its own command line or environment selects prod credentials**: `AWS_PROFILE=…`, `--profile` / `--aws-profile`, `--stage prod`, an exported variable, or a sourced env file that switches to prod. An explicit non-prod profile or stage always wins.

With nothing selected, it looks at **the code the command will run** (`python -c`, `node -e`, a heredoc, a script written earlier in the same command, or the script file on disk). It asks only if that code both selects the prod profile and makes an AWS **write** call: boto3 verbs, SDK v3 `*Command` classes, DocumentClient writes, CLI write operations, HTTP writes. Prod-read code passes. Code it can't see, running under prod credentials, asks.

A bare mention of the account id (in an ARN, a CDK account map, or docs) is data, not credential use.

### Shell it understands

Heredocs, `$( … )`, backticks and `$(( … ))` (each substitution is checked as its own command), `<( … )` process substitution, line continuations, wrappers (`env`, `sudo`, `timeout`, `xargs`, `npx`, `uvx`…), inline and exported variables, `cd` / `git -C`, and shell functions, whose bodies are checked where they're **called**, with the environment of that moment.

Nested shells (`bash -c`, `bash -lc`, `sh -ec`, a heredoc'd or script-file shell) and `eval` get their command lines checked with the same rules and the environment they inherit, and the outer checks still apply to them. A command whose name it can't see asks, at any depth: `$CMD`, `eval "$CMD"`, `bash -c '"$@"'`, `$(echo git) push`. A variable whose value is certain (assigned once in the same command, unconditionally, with `IFS` untouched) is expanded first, and an unquoted one holding a whole command line is split into it as bash does. A nested command line that reads a variable its own prefix assignment sets asks, because which value it sees depends on quoting.

It reads a command line the way bash does: a comment starts only at a word boundary (`# git push` after a space is a comment, the `#` in `x=a#` is not), a backslash-newline is deleted rather than turned into a space, `$'...'` strings honor their backslash escapes and end at a NUL, and each `$( … )` body is read in its own context.

## Tested like production code

```bash
python3 test_bash_guard.py      # 179/179 passed
python3 mutate_bash_guard.py    # 59 mutants, all KILLED
```

- **178 table cases** (allow / ask / deny), plus an end-to-end run of the `bash-guard.sh` fast path. Many are replays of real commands that the guard once got wrong in either direction.
- **59 mutants.** Each one removes or bends a single rule, for example "AWS non-read ops allowed", "explicit dev profile doesn't win", "function calls not expanded", "nested shells not analyzed", "any mention of the account id = prod". The table tests must fail for every mutant. A mutant that survives means that rule has no test protecting it.

Five rounds of security review found ways around earlier versions: commands nested in `bash -c`, `bash -lc` or `eval`; a mid-word `#`, a backslash-newline or a `$'...'` string that made the parser see a comment where bash sees code; a command hidden in a variable or a substitution's output; `AWS_DEFAULT_PROFILE`; an uppercase `--stage PROD`; and unparseable commands that were allowed. The second round also caught a regression from the first: a nested shell skipped the outer deploy-script check. Each fix started as a failing test and has its own mutant.

The tests build a throwaway workspace (two git repos, `acme/api` and `acme/web_app`, plus fixture scripts) and run with `BASH_GUARD_OFFLINE=1`, so they never call GitHub.

## Install

1. Copy `bash-guard.sh` and `bash_guard.py` into your project's `.claude/hooks/`.
2. Register the hook in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "bash \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/bash-guard.sh", "timeout": 30 }
        ]
      }
    ]
  }
}
```

3. Configure it through the environment:

| Variable | Meaning |
|---|---|
| `BASH_GUARD_PROD_ACCOUNT` | Your 12-digit prod AWS account id, as it appears in your profile names (for example `123456789012_AdministratorAccess`) |
| `BASH_GUARD_PROTECTED_REPO` | A repo whose `main` deploys to prod; pushes and merges into it always ask |

`bash-guard.sh` is a fast path: Python only starts when the command mentions a trigger word, so ordinary commands cost about 10 ms. If the guard itself crashes on a candidate command, it **asks** rather than silently allowing.

Requires Python 3.9+, `jq` and, for the merge and rerun prompts, the GitHub CLI.

## Limits

This is a guard against an agent's mistakes, not a security boundary against an attacker. It models bash; Claude Code runs commands in your login shell, and zsh (the macOS default) differs in places, such as glob qualifiers that can run code. Write detection is heuristic, and a determined process can always find a path the parser doesn't model. Its job is to make sure the risky commands an agent issues in normal work reach a human first.

## License

MIT
