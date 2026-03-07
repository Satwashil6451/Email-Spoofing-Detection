# src/features.py

from typing import Dict, Any
from urllib.parse import urlparse

# List of commonly used phishing-related keywords.

# These words often appear in scam emails trying to create urgency or steal credentials.
SUSPICIOUS_KEYWORDS = [
    "verify", "account", "password", "urgent", "click", "confirm", "security", "bank", "login", "ssn", "invoice"
]

def domain_of_url(url: str) -> str:
    try:
        # Parse the URL using urllib
        p = urlparse(url)
        # Extract and return the domain (netloc), convert to lowercase and remove any accidental spaces.
        # Example: https://paypal.com/login → paypal.com
        return p.netloc.lower().strip()
    except Exception:
        # If URL parsing fails, return empty string
        return ""
        
def extract_simple_features(parsed_email: Dict[str, Any], protocol_checks: Dict[str, Any]) -> Dict[str, Any]:
    feats = {}

    # Sender's domain extracted from the "From" header
    # Example: support@paypal.com → paypal.com
    feats["from_domain"] = parsed_email.get("from_domain", "")

    # Domain from Return-Path header (used in email routing)
    # Phishing emails often mismatch this with the visible sender.

    feats["return_path_domain"] = parsed_email.get("return_path_domain", "")

    # Domain extracted from Message-ID header
    # Message-ID should usually align with legitimate sending domain.
    feats["message_id_domain"] = parsed_email.get("message_id_domain", "")

    # Total number of URLs found inside the email
    # Phishing emails usually contain multiple malicious links.
    feats["num_urls"] = len(parsed_email.get("urls", []))

    # Number of attachments included in the email
    # Suspicious emails often include malware attachments.
    feats["num_attachments"] = len(parsed_email.get("attachments", []))

    # Length of plain text content in the email body
    # Extremely short or very long messages can be suspicious.
    feats["text_len"] = len(parsed_email.get("text", "") or "")

    # Length of HTML content in the email body
    # Phishing emails often rely heavily on HTML formatting.
    feats["html_len"] = len(parsed_email.get("html", "") or "")
    
    # Ratio of HTML length to text length.
    # High ratio may indicate heavily formatted phishing email.
    # +1 added to avoid division by zero.
    feats["html_to_text_ratio"] = (feats["html_len"] / (feats["text_len"]+1)) if feats["text_len"] >= 0 else 0.0

    # Combine email body text and subject for keyword scanning
    txt = (parsed_email.get("text", "") or "") + " " + (parsed_email.get("subject", "") or "")
    lc = txt.lower()

    # Count how many suspicious keywords appear in email text.
    # More suspicious words → higher phishing probability.
    feats["suspicious_keyword_count"] = sum(1 for k in SUSPICIOUS_KEYWORDS if k in lc)

    # Count URLs whose domain does NOT match the sender's domain.
    # Example:
    # From: paypal.com
    # Link: http://secure-login-paypal.xyz → mismatch → suspicious
    from_domain = feats["from_domain"]
    mismatch = 0
    for u in parsed_email.get("urls", []):
        d = domain_of_url(u)
        # If URL domain exists and sender domain exists
        # and sender domain is not part of URL domain → mismatch
        if d and from_domain and from_domain not in d:
            mismatch += 1
    feats["url_domain_mismatch_count"] = mismatch

    # Whether DKIM validation passed (True/False)
    # DKIM ensures email content wasn't tampered with.
    feats["dkim_valid"] = bool(protocol_checks.get("dkim_valid"))

    # SPF result (pass, fail, softfail, none, etc.)
    # SPF checks if sending server is authorized.
    spf = protocol_checks.get("spf_result", "none")
    feats["spf_result"] = spf

    # DMARC policy of sender's domain (none, quarantine, reject)
    # Strong DMARC policies improve legitimacy.
    feats["dmarc_policy"] = protocol_checks.get("dmarc_policy")

    # True if "From" domain and Return-Path domain do not match.
    # Mismatch often indicates spoofing.
    feats["from_vs_returnpath_mismatch"] = (
        (feats["from_domain"] != feats["return_path_domain"])
        and bool(feats["return_path_domain"])
    )

    # True if Message-ID domain and From domain do not match.
    # Another spoofing detection signal.
    feats["messageid_vs_from_mismatch"] = (
        (feats["message_id_domain"] != feats["from_domain"])
        and bool(feats["message_id_domain"])
    )

    return feats
