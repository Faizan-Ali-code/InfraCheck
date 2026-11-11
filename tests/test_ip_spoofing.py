"""IP Spoofing Analysis compares every spoofed request with a baseline instead of trusting any 200."""

import os
import tempfile
import unittest
from unittest import mock

from infrachecker import config
from infrachecker.scanners import ip_spoofing as spoof
from infrachecker.scanners._page_checks import Page

SERVED = spoof.Observation(200, Page.OK, "<html>admin console</html>")
FORBIDDEN = spoof.Observation(403, Page.OTHER, "Forbidden")
LOGIN_REDIRECT = spoof.Observation(302, Page.EMPTY, "")
NOT_FOUND = spoof.Observation(404, Page.NOT_FOUND, "The requested URL was not found on this server")
FAILED = spoof.Observation(0, None, "", "SocketTimeoutException: Read timed out")


class JudgeTest(unittest.TestCase):
    def test_public_page_is_not_reported_vulnerable(self):
        self.assertEqual(spoof.judge(SERVED, SERVED)[0], spoof.NOT_APPLICABLE)

    def test_refused_then_served_is_vulnerable(self):
        self.assertEqual(spoof.judge(FORBIDDEN, SERVED)[0], spoof.VULNERABLE)
        self.assertEqual(spoof.judge(LOGIN_REDIRECT, SERVED)[0], spoof.VULNERABLE)

    def test_header_ignored_is_not_vulnerable(self):
        self.assertEqual(spoof.judge(FORBIDDEN, FORBIDDEN)[0], spoof.NOT_VULNERABLE)

    def test_changed_but_not_served_needs_review(self):
        self.assertEqual(spoof.judge(FORBIDDEN, NOT_FOUND)[0], spoof.REVIEW)

    def test_error_page_with_200_is_not_served(self):
        waf_block = spoof.Observation(200, Page.WAF_BLOCK, "The requested URL was rejected.")
        self.assertFalse(waf_block.served)
        self.assertEqual(spoof.judge(FORBIDDEN, waf_block)[0], spoof.REVIEW)

    def test_failures_are_unable_to_test(self):
        self.assertEqual(spoof.judge(FAILED, SERVED)[0], spoof.UNABLE)
        self.assertEqual(spoof.judge(FORBIDDEN, FAILED)[0], spoof.UNABLE)


class InputTest(unittest.TestCase):
    def test_forwarded_header_uses_rfc7239_syntax(self):
        self.assertEqual(spoof.header_value("X-Forwarded-For", "10.0.0.1"), "10.0.0.1")
        self.assertEqual(spoof.header_value("Forwarded", "10.0.0.1"), "for=10.0.0.1")
        self.assertEqual(spoof.header_value("Forwarded", "::1"), 'for="[::1]"')

    def test_spoof_file_values_are_validated_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "spoof-ips.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("# office\n203.0.113.7\nnot-an-ip\n203.0.113.7\n::1\n")
            self.assertEqual(spoof.load_spoof_values(path), ["203.0.113.7", "::1"])

    def test_defaults_when_file_missing_or_empty(self):
        self.assertEqual(spoof.load_spoof_values("does-not-exist.txt"), list(config.DEFAULT_SPOOF_IPS))


class ScanTest(unittest.TestCase):
    def test_rows_compare_against_the_baseline(self):
        rows = []
        responses = {header: (SERVED if header == "X-Forwarded-For" else FORBIDDEN) for header in spoof.SPOOF_HEADERS}

        def fake_fetch(url, extra_headers):
            return responses[extra_headers[0][0]]

        with mock.patch.object(spoof, "fetch", side_effect=fake_fetch), \
                mock.patch.object(spoof._page_checks, "record", side_effect=lambda out, row, path, body: rows.append(row)), \
                mock.patch.object(spoof.writer, "append_row", side_effect=lambda out, row: rows.append(row)):
            spoof.scan_ip("https://intranet.example", "10.0.0.1", "out.xlsx", "T1", 1, baseline=FORBIDDEN)

        self.assertEqual(len(rows), len(spoof.SPOOF_HEADERS))
        verdicts = {row.split("\t")[2]: row.split("\t")[5] for row in rows}
        self.assertEqual(verdicts["X-Forwarded-For"], spoof.VULNERABLE)
        self.assertEqual({v for h, v in verdicts.items() if h != "X-Forwarded-For"}, {spoof.NOT_VULNERABLE})
        self.assertTrue(all(len(row.split("\t")) == len(config.IP_SPOOFING_COLUMNS) for row in rows))


if __name__ == "__main__":
    unittest.main()
