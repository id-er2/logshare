import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

import logshare


def redact(text):
    return logshare.Redactor().redact_text(text)


class RedactionRuleTests(unittest.TestCase):
    def test_email_is_masked(self):
        out = redact("user bob@example.com logged in")
        self.assertIn("[EMAIL_1]", out)
        self.assertNotIn("bob@example.com", out)

    def test_same_email_gets_same_label(self):
        out = redact("bob@example.com then bob@example.com")
        self.assertEqual(out.count("[EMAIL_1]"), 2)

    def test_different_emails_get_different_labels(self):
        out = redact("a@x.com and b@y.net")
        self.assertIn("[EMAIL_1]", out)
        self.assertIn("[EMAIL_2]", out)

    def test_ipv4_is_masked(self):
        out = redact("GET / from 192.168.1.10 ok")
        self.assertIn("[IP_1]", out)
        self.assertNotIn("192.168.1.10", out)

    def test_invalid_ipv4_octet_is_kept(self):
        out = redact("version 256.1.1.1 built")
        self.assertIn("256.1.1.1", out)

    def test_ipv6_is_masked(self):
        out = redact("client fe80::1 connected")
        self.assertIn("[IPV6_1]", out)
        self.assertNotIn("fe80::1", out)

    def test_ipv6_loopback_is_masked(self):
        out = redact("listening on ::1 port 80")
        self.assertIn("[IPV6_1]", out)

    def test_double_colon_code_is_kept(self):
        out = redact("rust path std::fmt::Debug here")
        self.assertIn("std::fmt::Debug", out)

    def test_authorization_header_keeps_scheme(self):
        out = redact("Authorization: Bearer abc.def.ghi")
        self.assertIn("Authorization: Bearer [AUTH_HEADER_1]", out)
        self.assertNotIn("abc.def.ghi", out)

    def test_password_value_is_masked_key_kept(self):
        out = redact("password=Sup3rSecret! done")
        self.assertIn("password=[CREDENTIAL_1]", out)
        self.assertNotIn("Sup3rSecret!", out)

    def test_quoted_secret_keeps_quotes(self):
        out = redact('api_key="s3cr3tvalue" next')
        self.assertIn('api_key="[CREDENTIAL_1]"', out)

    def test_jwt_is_masked(self):
        out = redact("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdef here")
        self.assertIn("[TOKEN_1]", out)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", out)

    def test_aws_key_is_masked(self):
        out = redact("aws access key AKIAIOSFODNN7EXAMPLE in log")
        self.assertIn("[TOKEN_1]", out)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)

    def test_github_token_is_masked(self):
        out = redact("ghp_" + "a1b2c3d4e5" * 3 + " leaked")
        self.assertNotIn("ghp_", out)
        self.assertIn("[TOKEN_1]", out)

    def test_url_userinfo_is_masked_host_kept(self):
        out = redact("GET https://admin:hunter2@db.internal:5432/x")
        self.assertIn("https://[CREDENTIALS_1]@db.internal", out)
        self.assertNotIn("hunter2", out)

    def test_cookie_values_masked_names_kept(self):
        out = redact("Cookie: sessionid=abc123xyz; theme=light")
        self.assertIn("sessionid=[COOKIE_1]", out)
        self.assertIn("theme=[COOKIE_2]", out)
        self.assertNotIn("abc123xyz", out)

    def test_private_key_block_is_masked(self):
        text = "-----BEGIN PRIVATE KEY-----\nline1\nline2\n-----END PRIVATE KEY-----\nafter"
        out = redact(text)
        self.assertIn("[PRIVATE_KEY_1]", out)
        self.assertNotIn("line1", out)
        self.assertIn("after", out)

    def test_json_sensitive_field_is_masked(self):
        line = '{"user": "sam", "token": "t0psecret"}'
        out = redact(line)
        parsed = json.loads(out)
        self.assertEqual(parsed["user"], "sam")
        self.assertEqual(parsed["token"], "[TOKEN_1]")

    def test_json_nested_field_is_masked(self):
        line = '{"req": {"headers": {"authorization": "Bearer xyz123"}}}'
        out = redact(line)
        parsed = json.loads(out)
        self.assertEqual(parsed["req"]["headers"]["authorization"], "[AUTHORIZATION_1]")

    def test_json_email_in_normal_field_is_masked(self):
        line = '{"contact": "mail me at sam@corp.io please"}'
        out = redact(line)
        parsed = json.loads(out)
        self.assertIn("[EMAIL_1]", parsed["contact"])

    def test_clean_log_is_unchanged(self):
        line = "2026-11-19 INFO service started on port 8080"
        self.assertEqual(redact(line), line)


class ReportTests(unittest.TestCase):
    def test_report_counts_unique_values(self):
        r = logshare.Redactor()
        r.redact_text("bob@example.com and bob@example.com and ana@x.io")
        report = r.report()
        self.assertEqual(report["email address"]["redactions"], 3)
        self.assertEqual(report["email address"]["unique_values"], 2)

    def test_report_has_no_secret_values(self):
        r = logshare.Redactor()
        r.redact_text("password=Sup3rSecret! email bob@example.com")
        rendered = io.StringIO()
        logshare.print_report(r.report(), rendered)
        self.assertNotIn("Sup3rSecret!", rendered.getvalue())
        self.assertNotIn("bob@example.com", rendered.getvalue())

    def test_empty_report_mentions_no_matches(self):
        rendered = io.StringIO()
        logshare.print_report({}, rendered)
        self.assertIn("nothing matched", rendered.getvalue())


class CliTests(unittest.TestCase):
    def run_cli(self, argv, stdin_text=""):
        out, err = io.StringIO(), io.StringIO()
        old_stdin = logshare.sys.stdin
        logshare.sys.stdin = io.StringIO(stdin_text)
        try:
            with redirect_stdout(out), redirect_stderr(err):
                code = logshare.main(argv)
        finally:
            logshare.sys.stdin = old_stdin
        return code, out.getvalue(), err.getvalue()

    def test_stdin_redaction_to_stdout(self):
        code, out, err = self.run_cli([], "ip 10.0.0.5\n")
        self.assertEqual(code, 0)
        self.assertIn("[IP_1]", out)
        self.assertIn("redacted", err)

    def test_preview_shows_diff(self):
        code, out, _ = self.run_cli(["--preview"], "ip 10.0.0.5\n")
        self.assertEqual(code, 0)
        self.assertIn("-ip 10.0.0.5", out)
        self.assertIn("+ip [IP_1]", out)

    def test_report_only_prints_no_content(self):
        code, out, _ = self.run_cli(["--report"], "ip 10.0.0.5\n")
        self.assertEqual(code, 0)
        self.assertNotIn("[IP_1]", out)
        self.assertIn("IPv4 address", out)

    def test_rules_listing(self):
        code, out, _ = self.run_cli(["--rules"])
        self.assertEqual(code, 0)
        self.assertIn("email address", out)
        self.assertIn("[EMAIL_1]", out)

    def test_output_file(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "in.log")
            dst = os.path.join(tmp, "out.log")
            with open(src, "w", encoding="utf-8") as fh:
                fh.write("secret password=hunter2\n")
            code, _, _ = self.run_cli([src, "-o", dst])
            self.assertEqual(code, 0)
            with open(dst, encoding="utf-8") as fh:
                self.assertIn("password=[CREDENTIAL_1]", fh.read())

    def test_no_json_flag_treats_json_as_text(self):
        line = '{"token": "t0psecret"}'
        code, out, _ = self.run_cli(["--no-json"], line)
        self.assertEqual(code, 0)
        # as plain text the token keyword rule still masks the value
        self.assertIn('"token": "[CREDENTIAL_1]"', out)


if __name__ == "__main__":
    unittest.main()
