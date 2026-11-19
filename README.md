# logshare

A local log redactor written in Python. It masks emails, IP addresses,
credentials, tokens and cookies in a log file before you share that log
with vendor support, a forum, or an AI tool.

Everything runs on your machine. The log is never stored, sent, or
uploaded anywhere, and there are no dependencies beyond the Python
standard library.

## What it masks

- Email addresses: `bob@example.com` becomes `[EMAIL_1]`
- IPv4 and IPv6 addresses: `192.168.1.10` becomes `[IP_1]`
- Authorization headers (the scheme is kept):
  `Authorization: Bearer ...` becomes `Authorization: Bearer [AUTH_HEADER_1]`
- Credentials in `key=value` form: `password`, `token`, `api_key`,
  `secret`, `client_secret`, `aws_secret_access_key` and similar keys
- Well-known token formats: JWTs, AWS key IDs, GitHub, Slack and
  Google API keys
- Cookie values (the cookie names are kept):
  `sessionid=abc123` becomes `sessionid=[COOKIE_1]`
- Username:password inside URLs: `https://user:pass@host` becomes
  `https://[CREDENTIALS_1]@host`
- PEM private key blocks

The same sensitive value always gets the same placeholder within one
run, so a request or conversation can still be followed through the
log. The mapping from placeholder to real value is kept in memory only
and is never written out.

JSON log lines are parsed as JSON: sensitive fields (`token`,
`authorization`, `cookie`, ...) are masked by field name, and the same
rules are applied inside every other string value. Pass `--no-json` to
treat every line as plain text.

## Usage

Redact a log and print the result:

```
python3 logshare.py app.log
```

Pipe a log in, or paste one (Ctrl-D to finish):

```
cat app.log | python3 logshare.py
```

Write the redacted log to a new file (the original is never modified):

```
python3 logshare.py app.log -o app.clean.log
```

Preview the changes as a before/after diff:

```
python3 logshare.py app.log --preview
```

Print only the summary of what was found (counts, never the values):

```
python3 logshare.py app.log --report
```

List the redaction rules:

```
python3 logshare.py --rules
```

Example output:

```
2026-11-19 INFO user [EMAIL_1] logged in from [IP_1]
Authorization: Bearer [AUTH_HEADER_1]
password=[CREDENTIAL_1]
```

and the summary on stderr:

```
logshare: redacted 3 value(s):
  email address          1 redaction(s), 1 unique value(s)
  IPv4 address           1 redaction(s), 1 unique value(s)
  credential in key=value 1 redaction(s), 1 unique value(s)
Review the output before sharing it: pattern-based redaction can miss
secrets or mask harmless text.
```

## Tests

```
python3 -m unittest -v test_logshare
```

30 tests cover the redaction rules, the summary report and the command
line interface. All test data is synthetic.

## Notes

A redactor like this is a filter, not a guarantee. Pattern-based
redaction can miss secrets (an unusual key name, an unexpected format)
and can mask harmless text (a string that only looks like an IP
address). Always review the output yourself before you share it. The
tool never uploads anything and never keeps a copy of the original log
or of the removed values, so the review step is yours.

## License

MIT
