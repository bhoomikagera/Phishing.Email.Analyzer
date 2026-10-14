# Phishing Email Analyzer

A command-line tool, written in Python (standard library only), that reads an email
and gives it a **risk score from 0 to 100** with a plain-English explanation of every
warning sign it found.

## Why I built it
Phishing emails are one of the most common ways attackers get into accounts. I wanted
to understand what makes a phishing email look suspicious and turn those signs into
rules a program can check and explain.

## How it works
The analyzer reads the sender, subject and body, pulls out every link, and runs a set
of rules. Each rule that fires adds points to the score:

| Rule | What it looks for |
|------|-------------------|
| Urgent language | Pressure wording like "within 24 hours" or "final notice" |
| Asks for sensitive information | "Verify your password", "enter your social insurance number" |
| Mismatched link | Link text shows one website, but the link goes somewhere else |
| Lookalike domain | Fake versions of known brands (`micr0soft-support.com`, `accounts.google.com.security-alert.net`) |
| Sender doesn't match name | "PayPal Security" sent from a non-PayPal address |
| Link uses an IP address | `http://203.0.113.45/login` |
| Shortened link | `bit.ly` and similar |
| Suspicious domain ending | `.xyz`, `.top`, `.club`, etc. on non-official domains |
| Generic greeting | "Dear customer" instead of your name |
| Risky attachment | Mentions of `.zip`, `.exe` and similar files |
| Prize or money bait | "You have won", "gift card" |
| Insecure link | `http://` instead of `https://` |

Ratings: **Low** (under 20), **Medium** (20-39), **High** (40 and above).

## Usage
Analyze one email (a plain text file with `From:` and `Subject:` lines, a blank line,
then the body):

    python analyzer.py example_email.txt
    python analyzer.py example_email.txt --json

Run it on all 40 sample emails and see how it performed:

    python evaluate.py

Run the unit tests:

    python -m unittest -v

## Files
- `analyzer.py` - the analyzer (rules, scoring, command-line interface)
- `evaluate.py` - runs the analyzer on `sample_emails.json` and prints accuracy
- `sample_emails.json` - 40 sample emails I wrote (20 phishing, 20 legitimate)
- `test_analyzer.py` - unit tests for the helpers and rules
- `example_email.txt` - a sample input file

## Results
On the 40 sample emails, the analyzer scored every email, caught 16 of 20 phishing
emails, and flagged none of the 20 legitimate ones (90% accuracy).

## Limitations
- The sample emails are ones I wrote myself, and I adjusted the rules while testing on
  them, so the accuracy is likely higher than it would be on real-world emails.
- The four missed phishing emails were the ones with fewer signs: a prize scam, a
  fake payroll email, a fake survey, and a gift-card request with no links.
- It only checks rules. It does not use machine learning or look up live domain
  information, and it only knows the brands listed in `BRANDS`.
- It should be used as a learning tool, not as real security protection.

## Ideas for improvement
- Add more brands and a larger, real-world email dataset
- Check email headers (SPF/DKIM results)
- Weight the rules using a simple statistical model instead of fixed points
