"""
Run the analyzer on every email in sample_emails.json and report how it did.

Usage:
    python evaluate.py
"""
import json
from analyzer import analyze


def main():
    with open("sample_emails.json", encoding="utf-8") as fh:
        emails = json.load(fh)

    tp = fp = tn = fn = 0
    print(f"{'#':>2}  {'Actual':<10} {'Score':>5}  {'Rating':<7} Subject")
    print("-" * 70)
    for e in emails:
        result = analyze(e["from"], e["subject"], e["body"])
        predicted_phishing = result["rating"] == "High"
        actual_phishing = e["label"] == "phishing"
        if predicted_phishing and actual_phishing:
            tp += 1
        elif predicted_phishing and not actual_phishing:
            fp += 1
        elif not predicted_phishing and not actual_phishing:
            tn += 1
        else:
            fn += 1
        flag = "" if predicted_phishing == actual_phishing else "   <-- WRONG"
        print(f"{e['id']:>2}  {e['label']:<10} {result['score']:>5}  {result['rating']:<7} {e['subject'][:38]}{flag}")

    total = len(emails)
    print("-" * 70)
    print(f"Emails tested:                 {total}")
    print(f"Phishing caught (true pos):    {tp}")
    print(f"Phishing missed (false neg):   {fn}")
    print(f"Legit flagged (false pos):     {fp}")
    print(f"Legit passed (true neg):       {tn}")
    print(f"Accuracy:                      {(tp + tn) / total:.0%}")


if __name__ == "__main__":
    main()
