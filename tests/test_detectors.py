"""Detector behaviour, including the rule that matters most: never emit the value."""
import unittest

from kbscan import detectors


class TestRedactionIsUnconditional(unittest.TestCase):
    """A scanner that prints what it found is a second copy of the problem."""

    def test_finding_never_carries_the_matched_value(self):
        text = "SSN: 123-45-6789"
        findings = detectors.scan_text(text, salt=b"s")
        self.assertTrue(findings)
        for f in findings:
            blob = repr(f)
            self.assertNotIn("123-45-6789", blob)
            self.assertNotIn("6789", blob, "last-4 is still identifying")

    def test_same_value_in_two_places_shares_a_fingerprint(self):
        a = detectors.scan_text("ssn 123-45-6789", salt=b"s")[0]
        b = detectors.scan_text("SSN:  123 45 6789", salt=b"s")[0]
        self.assertEqual(a.fingerprint, b.fingerprint, "normalise before fingerprinting")

    def test_fingerprint_changes_with_salt(self):
        a = detectors.scan_text("ssn 123-45-6789", salt=b"one")[0]
        b = detectors.scan_text("ssn 123-45-6789", salt=b"two")[0]
        self.assertNotEqual(a.fingerprint, b.fingerprint)


class TestGovernmentIdentifier(unittest.TestCase):
    def test_detects_a_plausible_ssn(self):
        self.assertEqual(
            [f.detector for f in detectors.scan_text("123-45-6789", salt=b"s")], ["gov-id"]
        )

    def test_rejects_structurally_invalid_ssns(self):
        for bad in ("000-45-6789", "666-45-6789", "900-45-6789", "123-00-6789", "123-45-0000"):
            self.assertEqual(detectors.scan_text(bad, salt=b"s"), [], bad)

    def test_ignores_a_phone_number(self):
        self.assertEqual(detectors.scan_text("call 555-867-5309", salt=b"s"), [])


class TestPaymentCard(unittest.TestCase):
    def test_luhn_valid_number_is_reported(self):
        self.assertEqual(
            [f.detector for f in detectors.scan_text("4111 1111 1111 1111", salt=b"s")],
            ["payment-card"],
        )

    def test_luhn_invalid_number_is_not_reported(self):
        self.assertEqual(detectors.scan_text("4111 1111 1111 1112", salt=b"s"), [])

    def test_luhn_valid_number_without_a_card_network_prefix_is_not_reported(self):
        """Luhn passes one random digit string in ten. The prefix does the real filtering."""
        for n in ("1234567890123452", "8000123456789018", "9900123456789017"):
            self.assertEqual(detectors.scan_text(n, salt=b"s"), [], n)

    def test_each_major_network_prefix_is_still_reported(self):
        cases = {
            "visa": "4111111111111111",
            "mastercard": "5555555555554444",
            "mastercard-2series": "2223003122003222",
            "amex": "378282246310005",
            "discover": "6011111111111117",
        }
        for name, n in cases.items():
            self.assertEqual([f.detector for f in detectors.scan_text(n, salt=b"s")],
                             ["payment-card"], name)


class TestCredentials(unittest.TestCase):
    def test_private_key_header(self):
        text = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"
        self.assertIn("private-key", [f.detector for f in detectors.scan_text(text, salt=b"s")])

    def test_connection_string_with_inline_password(self):
        text = "postgres://app:hunter2@db.internal:5432/prod"
        self.assertIn("connection-string", [f.detector for f in detectors.scan_text(text, salt=b"s")])

    def test_connection_string_without_password_is_ignored(self):
        self.assertEqual(detectors.scan_text("postgres://db.internal:5432/prod", salt=b"s"), [])


class TestRosterNames(unittest.TestCase):
    """The identifiers that leak are the ones nobody thought to enumerate."""

    def test_roster_name_is_detected_case_insensitively(self):
        found = detectors.scan_text("Seen by Dr. Aurelia Vance", salt=b"s", roster=["aurelia vance"])
        self.assertEqual([f.detector for f in found], ["roster-name"])

    def test_roster_name_is_not_emitted(self):
        found = detectors.scan_text("Aurelia Vance", salt=b"s", roster=["Aurelia Vance"])
        self.assertNotIn("Aurelia", repr(found[0]))

    def test_no_roster_means_no_roster_findings(self):
        self.assertEqual(detectors.scan_text("Aurelia Vance", salt=b"s"), [])


class TestDeclaredSensitivity(unittest.TestCase):
    """Front matter that already says what it is should be believed."""

    def test_visibility_sensitive_in_front_matter(self):
        text = "---\ntitle: x\nvisibility: sensitive\n---\nbody\n"
        self.assertIn("declared-sensitive", [f.detector for f in detectors.scan_text(text, salt=b"s")])

    def test_visibility_public_is_not_a_finding(self):
        text = "---\nvisibility: public\n---\nbody\n"
        self.assertEqual(detectors.scan_text(text, salt=b"s"), [])


if __name__ == "__main__":
    unittest.main()
