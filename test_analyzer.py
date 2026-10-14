"""Unit tests for the analyzer. Run with:  python -m unittest -v"""
import unittest
from analyzer import (analyze, extract_links, registered_domain, normalise, is_ip)


def rules(result):
    return {f["rule"] for f in result["findings"]}


class TestHelpers(unittest.TestCase):
    def test_registered_domain(self):
        self.assertEqual(registered_domain("accounts.google.com"), "google.com")
        self.assertEqual(registered_domain("www.cra-arc.gc.ca"), "cra-arc.gc.ca")

    def test_ip_detection(self):
        self.assertTrue(is_ip("203.0.113.45"))
        self.assertFalse(is_ip("example.com"))

    def test_normalise_swaps(self):
        self.assertEqual(normalise("micr0soft"), "microsoft")
        self.assertEqual(normalise("paypa1"), "paypal")

    def test_extract_links_html_and_plain(self):
        links = extract_links('<a href="http://a.com/x">a.com</a> and https://b.org/y')
        self.assertIn(("http://a.com/x", "a.com"), links)
        self.assertIn(("https://b.org/y", None), links)


class TestRules(unittest.TestCase):
    def test_legit_email_scores_low(self):
        r = analyze("PayPal <service@paypal.com>", "Receipt",
                    '<a href="https://www.paypal.com/activity">paypal.com/activity</a>')
        self.assertEqual(r["rating"], "Low")
        self.assertEqual(r["findings"], [])

    def test_mismatched_link(self):
        r = analyze("a@b.com", "Hi", '<a href="http://evil.com/x">www.paypal.com/login</a>')
        self.assertIn("Mismatched link", rules(r))

    def test_lookalike_domain(self):
        r = analyze("a@b.com", "Hi", "Go to https://micr0soft-support.com/login")
        self.assertIn("Lookalike domain", rules(r))

    def test_brand_as_subdomain_is_flagged(self):
        r = analyze("a@b.com", "Hi", "https://accounts.google.com.security-alert.net/signin")
        self.assertIn("Lookalike domain", rules(r))

    def test_official_subdomain_not_flagged(self):
        r = analyze("a@b.com", "Hi", "https://accounts.google.com/signin")
        self.assertNotIn("Lookalike domain", rules(r))

    def test_ip_link(self):
        r = analyze("a@b.com", "Hi", "http://203.0.113.45/login")
        self.assertIn("Link uses an IP address", rules(r))

    def test_urgent_and_credentials(self):
        r = analyze("a@b.com", "Urgent", "Verify your password immediately")
        self.assertIn("Urgent language", rules(r))
        self.assertIn("Asks for sensitive information", rules(r))

    def test_sender_mismatch(self):
        r = analyze("PayPal Support <help@random-mail.com>", "Hi", "Hello")
        self.assertIn("Sender doesn't match name", rules(r))

    def test_score_capped_at_100(self):
        body = ('Dear customer, urgent: verify your password immediately within 24 hours. '
                'You have won a gift card. invoice.exe http://203.0.113.9/x http://bit.ly/z')
        r = analyze("PayPal <x@paypa1-secure.xyz>", "Final notice", body)
        self.assertLessEqual(r["score"], 100)
        self.assertEqual(r["rating"], "High")


if __name__ == "__main__":
    unittest.main()
