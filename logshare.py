#!/usr/bin/env python3
"""Local log redactor.

Masks emails, IP addresses, credentials, tokens and cookies in log files
before they are shared with vendors, forums or AI tools. Everything runs
on your machine: nothing is stored, logged or sent anywhere. There are no
dependencies beyond the Python standard library.

The same sensitive value always gets the same placeholder within one run
(for example IP_1, EMAIL_2), so a conversation or a request can still be
followed through the log. The mapping from placeholder to real value is
kept in memory only and is never written out.
"""

import argparse
import difflib
import json
import re
import sys
from collections import OrderedDict

# Rules are applied in order. Each rule has:
#   name    - shown in the summary report
#   prefix  - base of the placeholder, e.g. EMAIL -> EMAIL_1, EMAIL_2
#   regex   - must capture the sensitive part in a group named "secret"
#   keep    - groups that are kept as-is around the placeholder
RULES = [
    (
        "authorization header",
        "AUTH_HEADER",
        re.compile(
            r"(?P<key>\b(?:authorization|proxy-authorization|x-api-key|x-auth-token)\b)"
            r"(?P<sep>[\"']?\s*[:=]\s*[\"']?)"
            r"(?P<scheme>(?:bearer|basic|digest)\s+)?"
            r"(?P<secret>[^\s\"';},]+)",
            re.IGNORECASE,
        ),
    ),
    (
        "credential in key=value",
        "CREDENTIAL",
        re.compile(
            r"(?P<key>\b(?:token|api[_-]?key|apikey|access[_-]?token|"
            r"refresh[_-]?token|id[_-]?token|client[_-]?secret|secret|password|"
            r"passwd|pwd|private[_-]?key|session[_-]?token|auth[_-]?token|"
            r"aws_secret_access_key)\b)"
            r"(?P<sep>[\"']?\s*[:=]\s*[\"']?)"
            r"(?P<scheme>)"
            r"(?P<secret>[^\s\"';},]+)",
            re.IGNORECASE,
        ),
    ),
    (
        "well-known token format",
        "TOKEN",
        re.compile(
            r"(?P<key>)(?P<sep>)(?P<scheme>)"
            r"(?P<secret>"
            r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"   # JWT
            r"|AKIA[0-9A-Z]{16}"                                    # AWS access key id
            r"|ASIA[0-9A-Z]{16}"                                    # AWS temp key id
            r"|gh[pousr]_[A-Za-z0-9]{20,}"                          # GitHub tokens
            r"|github_pat_[A-Za-z0-9_]{22,}"
            r"|xox[baprs]-[A-Za-z0-9-]{10,}"                        # Slack tokens
            r"|AIza[0-9A-Za-z_-]{35}"                               # Google API key
            r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
            r")"
        ),
    ),
    (
        "URL userinfo",
        "CREDENTIALS",
        re.compile(r"(?P<key>://)(?P<sep>)(?P<scheme>)(?P<secret>[^/\s:@]+:[^/\s@]+)(?=@)"),
    ),
    (
        "email address",
        "EMAIL",
        re.compile(
            r"(?P<key>)(?P<sep>)(?P<scheme>)"
            r"(?P<secret>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
        ),
    ),
    (
        "IPv4 address",
        "IP",
        re.compile(
            r"(?<![\w.])"
            r"(?P<secret>(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
            r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})"
            r"(?![\w.])"
        ),
    ),
    (
        "IPv6 address",
        "IPV6",
        re.compile(
            r"(?<![0-9A-Za-z:])"
            r"(?P<secret>"
            r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
            r"|[0-9A-Fa-f]{1,4}:(?:(?::[0-9A-Fa-f]{1,4}){1,6})"
            r"|::(?:[0-9A-Fa-f]{1,4}:?){0,6}"
            r")"
            r"(?![0-9A-Fa-f:])"
        ),
    ),
]

COOKIE_RE = re.compile(
    r"(?P<key>\b(?:cookie|set-cookie)\b)(?P<sep>\s*[:=]\s*)(?P<pairs>[^\r\n]*)",
    re.IGNORECASE,
)
COOKIE_PAIR_RE = re.compile(r"(?P<name>[^=;\s]+)(?P<eq>=)(?P<value>[^;\s]*)")

PEM_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)

# JSON object keys whose whole value is replaced.
SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "access_token",
    "refresh_token", "id_token", "api_key", "apikey", "client_secret",
    "private_key", "authorization", "proxy_authorization", "proxy-authorization",
    "cookie", "set-cookie", "set_cookie", "session", "session_id", "auth",
    "auth_token", "x-api-key", "x_api_key", "x-auth-token", "x_auth_token",
    "aws_secret_access_key", "credentials",
}


class Redactor:
    """Applies the rules and keeps value -> placeholder maps in memory."""

    def __init__(self):
        self.maps = {name: OrderedDict() for name, _, _ in RULES}
        self.maps["cookie"] = OrderedDict()
        self.maps["json field"] = OrderedDict()
        self.maps["private key block"] = OrderedDict()
        self.counts = {name: 0 for name in self.maps}

    def _label(self, rule_name, prefix, value):
        mapping = self.maps[rule_name]
        if value not in mapping:
            # Brackets keep later rules from matching inside a placeholder
            # (for example an "@" left next to an IP-like label).
            mapping[value] = "[%s_%d]" % (prefix, len(mapping) + 1)
        self.counts[rule_name] += 1
        return mapping[value]

    def _apply_rule(self, text, name, prefix, regex):
        def repl(match):
            secret = match.group("secret")
            if not secret:
                return match.group(0)
            label = self._label(name, prefix, secret)
            parts = []
            for g in ("key", "sep", "scheme"):
                if g in match.re.groupindex:
                    parts.append(match.group(g) or "")
            return "".join(parts) + label

        return regex.sub(repl, text)

    def _redact_cookies(self, text):
        def repl(match):
            pairs = match.group("pairs")

            def pair_repl(pm):
                value = pm.group("value")
                if not value:
                    return pm.group(0)
                return pm.group("name") + pm.group("eq") + self._label(
                    "cookie", "COOKIE", value
                )

            return (
                match.group("key")
                + match.group("sep")
                + COOKIE_PAIR_RE.sub(pair_repl, pairs)
            )

        return COOKIE_RE.sub(repl, text)

    def _redact_json_strings(self, node):
        if isinstance(node, dict):
            out = {}
            for key, value in node.items():
                if key.lower() in SENSITIVE_KEYS and isinstance(value, str) and value:
                    out[key] = self._label(
                        "json field", re.sub(r"[^A-Z0-9]+", "_", key.upper()).strip("_"),
                        value,
                    )
                else:
                    out[key] = self._redact_json_strings(value)
            return out
        if isinstance(node, list):
            return [self._redact_json_strings(item) for item in node]
        if isinstance(node, str):
            return self.redact_line(node)
        return node

    def redact_line(self, line):
        line = self._redact_cookies(line)
        for name, prefix, regex in RULES:
            line = self._apply_rule(line, name, prefix, regex)
        return line

    def redact_text(self, text):
        def pem_repl(match):
            label = self._label("private key block", "PRIVATE_KEY", match.group(0))
            return "%s (%d lines removed)" % (label, match.group(0).count("\n") + 1)

        text = PEM_RE.sub(pem_repl, text)
        out_lines = []
        for line in text.splitlines(keepends=True):
            stripped = line.strip()
            if stripped.startswith(("{", "[")):
                try:
                    parsed = json.loads(stripped)
                except ValueError:
                    parsed = None
                if isinstance(parsed, (dict, list)):
                    redacted = self._redact_json_strings(parsed)
                    newline = "\n" if line.endswith("\n") else ""
                    out_lines.append(
                        json.dumps(redacted, ensure_ascii=False) + newline
                    )
                    continue
            out_lines.append(self.redact_line(line))
        return "".join(out_lines)

    def report(self):
        return {
            name: {"redactions": self.counts[name], "unique_values": len(self.maps[name])}
            for name in self.maps
            if self.counts[name]
        }


def print_report(report, stream):
    if not report:
        stream.write("logshare: nothing matched the redaction rules\n")
        return
    total = sum(r["redactions"] for r in report.values())
    stream.write("logshare: redacted %d value(s):\n" % total)
    for name, r in report.items():
        stream.write(
            "  %-22s %d redaction(s), %d unique value(s)\n"
            % (name, r["redactions"], r["unique_values"])
        )
    stream.write(
        "Review the output before sharing it: pattern-based redaction can "
        "miss secrets or mask harmless text.\n"
    )


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="logshare",
        description="Redact emails, IPs, credentials, tokens and cookies "
        "from a log file, locally. Reads FILE or standard input.",
    )
    parser.add_argument("file", nargs="?", help="log file to redact (default: stdin)")
    parser.add_argument("-o", "--output", help="write the redacted log here")
    parser.add_argument(
        "--preview",
        action="store_true",
        help="show a before/after diff instead of the redacted log",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="print only the redaction summary, not the log",
    )
    parser.add_argument(
        "--rules", action="store_true", help="list the redaction rules and exit"
    )
    parser.add_argument(
        "--no-json",
        action="store_true",
        help="treat every line as plain text (skip JSON field detection)",
    )
    args = parser.parse_args(argv)

    if args.rules:
        for name, prefix, _ in RULES:
            print("%-22s placeholder: [%s_1], [%s_2], ..." % (name, prefix, prefix))
        print("%-22s placeholder: [COOKIE_1], [COOKIE_2], ..." % "cookie value")
        print("%-22s placeholder: [KEY_1], [KEY_2], ..." % "sensitive JSON field")
        print("%-22s placeholder: [PRIVATE_KEY_1], ..." % "private key block")
        return 0

    if args.file and args.file != "-":
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()

    redactor = Redactor()
    if args.no_json:
        pem_note = redactor.redact_text("")  # no-op, keeps one code path
        redacted = PEM_RE.sub(
            lambda m: "%s (%d lines removed)"
            % (redactor._label("private key block", "PRIVATE_KEY", m.group(0)),
               m.group(0).count("\n") + 1),
            text,
        )
        redacted = "".join(
            redactor.redact_line(line) for line in redacted.splitlines(keepends=True)
        )
    else:
        redacted = redactor.redact_text(text)

    if args.report:
        print_report(redactor.report(), sys.stdout)
        return 0

    if args.preview:
        diff = difflib.unified_diff(
            text.splitlines(keepends=True),
            redacted.splitlines(keepends=True),
            fromfile="before",
            tofile="after",
        )
        sys.stdout.writelines(diff)
        print_report(redactor.report(), sys.stderr)
        return 0

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(redacted)
        print_report(redactor.report(), sys.stderr)
    else:
        sys.stdout.write(redacted)
        print_report(redactor.report(), sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
