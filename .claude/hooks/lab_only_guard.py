#!/usr/bin/env python3
"""PreToolUse guard — enforce CLAUDE.md NEVER #4: never target a non-lab machine.

STATIC logic (no docker-compose parsing). The lab fleet is published on localhost
ports, so "lab-only" == "localhost-only":

  * SSH / scp / sftp are ALLOWED only when the target host is one of
    localhost / 127.0.0.1 / ::1.  Any other host  -> DENY.
  * ALL WinRM is denied: Enter-PSSession, New-PSSession, Invoke-Command -ComputerName,
    Connect-WSMan, Test-WSMan, winrs.

Reads the Claude Code hook payload from stdin. Only ever emits a "deny"; when the
command is fine it stays silent (exit 0) so normal permission rules still apply.

Fail behaviour:
  * A connection is detected but the host cannot be parsed -> DENY (fail closed).
  * Any unexpected internal error -> exit 0 (fail open) so a parser bug never bricks
    the shell.  The static permission deny-rules in settings.json remain as backstop.
"""
import sys
import json
import re

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}

SSH_ARG_OPTS = set("bcDEeFIiJLlmOopQRSWw")
SCP_ARG_OPTS = set("cFiJloPS")

WINRM_RE = re.compile(
    r"\b(Enter-PSSession|New-PSSession|Invoke-Command|Connect-WSMan|Test-WSMan|winrs)\b",
    re.I,
)


def emit_deny(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def normalize_host(host):
    if not host:
        return None
    host = host.strip().strip('"').strip("'")
    host = re.sub(r"^[a-zA-Z]+://", "", host)      # strip scheme (ssh://)
    if "@" in host:
        host = host.rsplit("@", 1)[1]              # strip user@
    if host.startswith("[") and "]" in host:       # [ipv6]:port
        host = host[1:host.index("]")]
    elif host.count(":") == 1:                     # host:port / host:path
        host = host.split(":", 1)[0]
    return host.strip().lower() or None


def tokenize(cmd):
    return re.findall(r'"[^"]*"|\'[^\']*\'|\S+', cmd)


def ssh_positionals(tokens, arg_opts):
    out, i = [], 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":
            out.extend(tokens[i + 1:])
            break
        if tok.startswith("-") and len(tok) > 1:
            if not tok.startswith("--") and len(tok) == 2 and tok[-1] in arg_opts:
                i += 2
                continue
            i += 1
            continue
        out.append(tok)
        i += 1
    return out


def collect(cmd):
    """Return (detected, hosts). hosts is the list of remote targets found."""
    detected = False
    hosts = []

    for m in re.finditer(r'(?:^|(?<=[\s;&|(]))(ssh|scp|sftp|ssh-copy-id)\b', cmd):
        detected = True
        prog = m.group(1)
        rest = re.split(r'[;&|]|\n', cmd[m.end():], maxsplit=1)[0]
        toks = tokenize(rest)
        if prog in ("scp", "sftp"):
            for c in ssh_positionals(toks, SCP_ARG_OPTS):
                if ":" in c and not c.startswith("/") and not re.match(r'^[A-Za-z]:[\\/]', c):
                    hosts.append(c)
        else:
            pos = ssh_positionals(toks, SSH_ARG_OPTS)
            if pos:
                hosts.append(pos[0])

    if WINRM_RE.search(cmd):
        detected = True
        # WinRM has no lab equivalent — flag with a sentinel so it is always denied.
        hosts.append("<winrm>")

    return detected, hosts


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    try:
        cmd = payload.get("tool_input", {}).get("command", "")
        if not isinstance(cmd, str) or not cmd.strip():
            sys.exit(0)

        detected, raw_hosts = collect(cmd)
        if not detected:
            sys.exit(0)

        if any(h == "<winrm>" for h in raw_hosts):
            emit_deny(
                "Blocked: WinRM / PowerShell Remoting is not permitted from a dev session "
                "(CLAUDE.md NEVER #4 — never target a non-lab machine). The lab fleet is "
                "Linux-over-SSH on localhost only."
            )

        normalized = [normalize_host(h) for h in raw_hosts]
        normalized = [h for h in normalized if h]

        if not normalized:
            emit_deny(
                "Blocked: an SSH/scp/sftp connection was detected but the target host could "
                "not be parsed to confirm it is localhost. Denying (fail-closed)."
            )

        bad = [h for h in normalized if h not in ALLOWED_HOSTS]
        if bad:
            emit_deny(
                "Blocked SSH/scp/sftp to non-lab host(s): " + ", ".join(sorted(set(bad)))
                + ". Only localhost / 127.0.0.1 / ::1 (the local lab fleet) is allowed "
                "(CLAUDE.md NEVER #4)."
            )

        sys.exit(0)
    except Exception:
        sys.exit(0)


if __name__ == "__main__":
    main()
