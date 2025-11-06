# src/features.py
from typing import Dict, Any
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "verify", "account", "password", "urgent", "click", "confirm", "security", "bank", "login", "ssn", "invoice"
]

def domain_of_url(url: str) -> str:
    try:
        p = urlparse(url)
        return p.netloc.lower().strip()
    except Exception:
        return ""

def extract_simple_features(parsed_email: Dict[str, Any], protocol_checks: Dict[str, Any]) -> Dict[str, Any]:
    feats = {}
    feats["from_domain"] = parsed_email.get("from_domain", "")
    feats["return_path_domain"] = parsed_email.get("return_path_domain", "")
    feats["message_id_domain"] = parsed_email.get("message_id_domain", "")
    feats["num_urls"] = len(parsed_email.get("urls", []))
    feats["num_attachments"] = len(parsed_email.get("attachments", []))
    feats["text_len"] = len(parsed_email.get("text", "") or "")
    feats["html_len"] = len(parsed_email.get("html", "") or "")
    # payload ratio
    feats["html_to_text_ratio"] = (feats["html_len"] / (feats["text_len"]+1)) if feats["text_len"] >= 0 else 0.0

    # keyword count
    txt = (parsed_email.get("text", "") or "") + " " + (parsed_email.get("subject", "") or "")
    lc = txt.lower()
    feats["suspicious_keyword_count"] = sum(1 for k in SUSPICIOUS_KEYWORDS if k in lc)

    # url domain mismatch count (urls whose domain != from_domain)
    from_domain = feats["from_domain"]
    mismatch = 0
    for u in parsed_email.get("urls", []):
        d = domain_of_url(u)
        if d and from_domain and from_domain not in d:
            mismatch += 1
    feats["url_domain_mismatch_count"] = mismatch

    # protocol info
    feats["dkim_valid"] = bool(protocol_checks.get("dkim_valid"))
    spf = protocol_checks.get("spf_result", "none")
    feats["spf_result"] = spf
    feats["dmarc_policy"] = protocol_checks.get("dmarc_policy")

    # header mismatches
    feats["from_vs_returnpath_mismatch"] = (feats["from_domain"] != feats["return_path_domain"]) and bool(feats["return_path_domain"])
    feats["messageid_vs_from_mismatch"] = (feats["message_id_domain"] != feats["from_domain"]) and bool(feats["message_id_domain"])
    return feats
