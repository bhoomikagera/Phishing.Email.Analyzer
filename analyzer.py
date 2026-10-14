"""
Phishing Email Analyzer
-----------------------
A rule-based tool that reads an email (sender, subject, body) and gives it a
risk score from 0-100 with a plain-English explanation of every rule that fired.

Uses only the Python standard library.

Usage:
    python analyzer.py path/to/email.txt
    python analyzer.py path/to/email.txt --json

Email file format (plain text):
    From: PayPal Security <security@paypal-secure-login.com>
    Subject: Your account has been limited

    (blank line, then the body - plain text or HTML)
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from difflib import SequenceMatcher
from email.parser import Parser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Configuration: the "knowledge" the rules use. Edit these to tune the tool.
# --------------------------------------------------------------------------

# Brand keyword -> official domains for that brand.
BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com", "office365.com"],
    "amazon": ["amazon.com", "amazon.ca"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "zoom": ["zoom.us", "zoom.com"],
    "coinbase": ["coinbase.com"],
    "canada post": ["canadapost.ca", "canadapost-postescanada.ca"],
    "scotiabank": ["scotiabank.com"],
    "royal bank": ["rbc.com", "rbcroyalbank.com"],
    "guelph": ["uoguelph.ca"],
    "canada revenue": ["canada.ca", "cra-arc.gc.ca"],
}

# Domains ending like these need three labels to identify the owner.
MULTI_PART_SUFFIXES = {"gc.ca", "co.uk", "com.au", "on.ca"}

URGENT_PHRASES = [
    "urgent", "immediately", "act now", "within 24 hours", "within 48 hours",
    "final notice", "last warning", "expires today", "limited time",
    "will be suspended", "will be locked",
    "will be deactivated", "will expire", "as soon as possible", "asap",
    "action required",
]

CREDENTIAL_PHRASES = [
    "verify your password", "confirm your password", "enter your password",
    "keep your password", "verify your account", "confirm your identity",
    "update your billing", "billing information", "social insurance number",
    "social security number", "credit card number", "direct deposit information",
    "log in to confirm", "sign in to verify", "confirm your login",
]

PRIZE_PHRASES = [
    "you have won", "you've won", "congratulations", "gift card", "free coffee",
    "claim your prize", "lottery", "wire transfer", "refund of",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear client", "dear student", "dear sir/madam",
    "dear account holder", "dear member", "dear valued customer",
]

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "club", "work", "loan", "icu", "rest", "me", "info"}
RISKY_ATTACHMENTS = re.compile(r"\b[\w\-]+\.(exe|scr|zip|js|vbs|bat|iso|jar)\b", re.I)

# Points added when each rule fires.
POINTS = {
    "urgent_language_1": 10,
    "urgent_language_2": 18,
    "urgent_language_3": 25,
    "credential_request": 25,
    "mismatched_link": 30,
    "lookalike_domain": 35,
    "ip_address_link": 25,
    "url_shortener": 10,
    "suspicious_tld": 10,
    "generic_greeting": 8,
    "sender_mismatch": 25,
    "risky_attachment": 15,
    "prize_or_money": 12,
    "insecure_http": 8,
}

HIGH_RISK_AT = 40     # score at or above this -> "High"
MEDIUM_RISK_AT = 20   # score at or above this -> "Medium"


# --------------------------------------------------------------------------
# Helpers for reading links and domains
# --------------------------------------------------------------------------

class _LinkParser(HTMLParser):
    """Collects (href, visible text) for every <a> tag in an HTML body."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def extract_links(body):
    """Return a list of (url, visible_text_or_None) found in the body."""
    parser = _LinkParser()
    parser.feed(body)
    links = list(parser.links)
    seen = {url for url, _ in links}
    for url in re.findall(r"https?://[^\s<>\"')]+", body):
        if url not in seen:
            links.append((url, None))
            seen.add(url)
    return links


def host_of(url):
    """Lowercase hostname of a URL (adds a scheme if it's missing)."""
    if "://" not in url:
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def is_ip(host):
    return re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) is not None


def registered_domain(host):
    """'accounts.google.com' -> 'google.com'; 'x.cra-arc.gc.ca' -> 'cra-arc.gc.ca'."""
    if not host or is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def looks_like_domain(text):
    """True if visible link text looks like a web address, e.g. 'www.paypal.com/login'."""
    return re.match(r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(/\S*)?$", text.strip().lower()) is not None


def normalise(s):
    """Undo common character swaps used in fake domains (paypa1, micr0soft, rn -> m)."""
    s = s.lower()
    for fake, real in (("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("rn", "m"), ("vv", "w")):
        s = s.replace(fake, real)
    return s.replace("-", "")


def official_domains():
    return {d for domains in BRANDS.values() for d in domains}


def is_official(host):
    return registered_domain(host) in official_domains()


# --------------------------------------------------------------------------
# Result type
# --------------------------------------------------------------------------

@dataclass
class Finding:
    rule: str
    points: int
    explanation: str


# --------------------------------------------------------------------------
# The rules. Each one returns a list of Finding objects (empty = didn't fire).
# --------------------------------------------------------------------------

def rule_urgent_language(subject, body):
    text = f"{subject} {body}".lower()
    hits = [p for p in URGENT_PHRASES if p in text]
    if not hits:
        return []
    key = "urgent_language_" + str(min(len(hits), 3))
    return [Finding("Urgent language", POINTS[key],
                    "Pressure wording found: " + ", ".join(f'"{h}"' for h in hits[:4]))]


def rule_credential_request(subject, body):
    text = f"{subject} {body}".lower()
    hits = [p for p in CREDENTIAL_PHRASES if p in text]
    if not hits:
        return []
    return [Finding("Asks for sensitive information", POINTS["credential_request"],
                    "Requests private details: " + ", ".join(f'"{h}"' for h in hits[:3]))]


def rule_mismatched_links(links):
    """Visible text shows one website but the link actually goes to another."""
    findings = []
    for url, text in links:
        if not text or not looks_like_domain(text):
            continue
        shown = registered_domain(host_of(text))
        actual = registered_domain(host_of(url))
        if shown and actual and shown != actual:
            findings.append(Finding("Mismatched link", POINTS["mismatched_link"],
                                    f'Link text says "{text}" but it goes to {actual}'))
            break  # one finding is enough
    return findings


def rule_lookalike_domains(links, sender_host):
    """Domains that imitate a known brand but are not the brand's real domain."""
    findings = []
    hosts = [host_of(u) for u, _ in links]
    if sender_host:
        hosts.append(sender_host)
    reported = set()
    for host in hosts:
        if not host or is_ip(host) or is_official(host):
            continue
        reg = registered_domain(host)
        squashed = normalise(host)
        for brand, domains in BRANDS.items():
            keyword = brand.replace(" ", "")
            reason = None
            if keyword in squashed:
                reason = f'contains "{brand}" but is not an official {brand} domain'
            else:
                for official in domains:
                    ratio = SequenceMatcher(None, normalise(reg), normalise(official)).ratio()
                    if ratio >= 0.85:
                        reason = f"is very similar to the real domain {official}"
                        break
            if reason and reg not in reported:
                reported.add(reg)
                findings.append(Finding("Lookalike domain", POINTS["lookalike_domain"],
                                        f"{host} {reason}"))
                break
        if findings:
            break  # one finding is enough
    return findings


def rule_ip_links(links):
    for url, _ in links:
        if is_ip(host_of(url)):
            return [Finding("Link uses an IP address", POINTS["ip_address_link"],
                            f"{url} points to a raw IP address instead of a website name")]
    return []


def rule_url_shorteners(links):
    for url, _ in links:
        if registered_domain(host_of(url)) in URL_SHORTENERS:
            return [Finding("Shortened link", POINTS["url_shortener"],
                            f"{url} hides the real destination behind a link shortener")]
    return []


def rule_suspicious_tld(links, sender_host):
    hosts = [host_of(u) for u, _ in links] + ([sender_host] if sender_host else [])
    for host in hosts:
        if host and not is_ip(host) and host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS and not is_official(host):
            return [Finding("Suspicious domain ending", POINTS["suspicious_tld"],
                            f".{host.rsplit('.', 1)[-1]} domain seen: {host}")]
    return []


def rule_generic_greeting(body):
    text = re.sub(r"<[^>]+>", " ", body).lower()
    for g in GENERIC_GREETINGS:
        if g in text:
            return [Finding("Generic greeting", POINTS["generic_greeting"],
                            f'Uses "{g}" instead of your name')]
    return []


def rule_sender_mismatch(sender_name, sender_host):
    """Display name claims a brand, but the sending address is not from that brand."""
    if not sender_host:
        return []
    name = sender_name.lower()
    for brand, domains in BRANDS.items():
        if brand in name and registered_domain(sender_host) not in domains:
            return [Finding("Sender doesn't match name", POINTS["sender_mismatch"],
                            f'Sender says "{sender_name}" but the address is from {sender_host}')]
    return []


def rule_risky_attachment(subject, body):
    m = RISKY_ATTACHMENTS.search(f"{subject} {body}")
    if m:
        return [Finding("Risky attachment", POINTS["risky_attachment"],
                        f'Mentions a file "{m.group(0)}" with a risky file type')]
    return []


def rule_prize_or_money(subject, body):
    text = f"{subject} {body}".lower()
    hits = [p for p in PRIZE_PHRASES if p in text]
    if hits:
        return [Finding("Prize or money bait", POINTS["prize_or_money"],
                        "Money/prize wording: " + ", ".join(f'"{h}"' for h in hits[:3]))]
    return []


def rule_insecure_http(links):
    for url, _ in links:
        if url.lower().startswith("http://"):
            return [Finding("Insecure link", POINTS["insecure_http"],
                            f"{url} does not use HTTPS")]
    return []


# --------------------------------------------------------------------------
# Putting it together
# --------------------------------------------------------------------------

def analyze(sender, subject, body):
    """Analyze one email. Returns a dict with score, rating and findings."""
    sender_name, sender_addr = parseaddr(sender)
    sender_host = sender_addr.split("@")[-1].lower() if "@" in sender_addr else ""
    links = extract_links(body)

    findings = []
    findings += rule_urgent_language(subject, body)
    findings += rule_credential_request(subject, body)
    findings += rule_mismatched_links(links)
    findings += rule_lookalike_domains(links, sender_host)
    findings += rule_ip_links(links)
    findings += rule_url_shorteners(links)
    findings += rule_suspicious_tld(links, sender_host)
    findings += rule_generic_greeting(body)
    findings += rule_sender_mismatch(sender_name, sender_host)
    findings += rule_risky_attachment(subject, body)
    findings += rule_prize_or_money(subject, body)
    findings += rule_insecure_http(links)

    score = min(100, sum(f.points for f in findings))
    if score >= HIGH_RISK_AT:
        rating = "High"
    elif score >= MEDIUM_RISK_AT:
        rating = "Medium"
    else:
        rating = "Low"
    return {"score": score, "rating": rating, "findings": [asdict(f) for f in findings]}


def analyze_file(path):
    with open(path, encoding="utf-8") as fh:
        msg = Parser().parsestr(fh.read())
    body = msg.get_payload()
    return analyze(msg.get("From", ""), msg.get("Subject", ""), body)


def print_report(result, title=""):
    if title:
        print(title)
    print(f"Risk score: {result['score']}/100  ({result['rating']} risk)")
    if not result["findings"]:
        print("  No warning signs found.")
    for f in result["findings"]:
        print(f"  +{f['points']:<3} {f['rule']}: {f['explanation']}")


def main():
    ap = argparse.ArgumentParser(description="Rule-based phishing email analyzer")
    ap.add_argument("email_file", help="path to a plain-text email (From:, Subject:, blank line, body)")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    args = ap.parse_args()
    try:
        result = analyze_file(args.email_file)
    except OSError as err:
        sys.exit(f"Could not read file: {err}")
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result, title=f"Analysis of {args.email_file}")


if __name__ == "__main__":
    main()
