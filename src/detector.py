# src/detector.py

from .parser import parse_email
from .protocol_checks import check_dkim, check_spf, get_dmarc
from .features import extract_simple_features
from typing import Optional, Dict, Any

class Detector:
    def __init__(self):
        # thresholds / weights for simple scoring
        self.weights = {
            "spf_fail": 2.0,
            "dkim_fail": 3.0,
            "from_returnpath_mismatch": 2.0,
            "url_mismatch": 1.0,         # per url mismatch
            "suspicious_keywords": 0.8,  # per keyword
            "attachment": 0.5
        }
        self.threshold = 2.0  # score >= threshold => spoof

    def analyze_email(self, raw_bytes: bytes, sender_ip: Optional[str]=None, envelope_from: Optional[str]=None, helo: Optional[str]=None) -> Dict[str, Any]:
        parsed = parse_email(raw_bytes)

        # protocol checks
        dkim_res = check_dkim(raw_bytes)
        spf_res = check_spf(sender_ip, envelope_from, helo)
        dmarc_res = get_dmarc(parsed.get("from_domain") or "")

        proto = {
            "dkim_valid": dkim_res.get("dkim_valid"),
            "dkim_error": dkim_res.get("error"),
            "spf_result": spf_res.get("spf_result"),
            "spf_explain": spf_res.get("spf_explain"),
            "dmarc": dmarc_res.get("dmarc"),
            "dmarc_policy": dmarc_res.get("policy")
        }

        feats = extract_simple_features(parsed, {"dkim_valid": proto["dkim_valid"], "spf_result": proto["spf_result"], "dmarc_policy": proto["dmarc_policy"]})

        # scoring
        score = 0.0
        reasons = []

        # SPF
        spf_result = proto["spf_result"]
        if spf_result in ("fail", "softfail", "error"):
            score += self.weights["spf_fail"]
            reasons.append(f"SPF result: {spf_result}")
        elif spf_result == "pass":
            score -= 1.0
            reasons.append("SPF passed")

        # DKIM
        if not proto["dkim_valid"]:
            score += self.weights["dkim_fail"]
            reasons.append("DKIM missing/invalid")
        else:
            score -= 1.5
            reasons.append("DKIM valid")

        # DMARC policy
        if proto["dmarc_policy"] in ("reject", "quarantine"):
            # presence of strict DMARC decreases chance of spoof
            score -= 0.5
            reasons.append(f"DMARC policy: {proto['dmarc_policy']}")

        # From vs Return-Path mismatch
        if feats.get("from_vs_returnpath_mismatch"):
            score += self.weights["from_returnpath_mismatch"]
            reasons.append("From vs Return-Path domain mismatch")

        # URL domain mismatches
        um = feats.get("url_domain_mismatch_count", 0)
        if um > 0:
            score += um * self.weights["url_mismatch"]
            reasons.append(f"{um} URL domain(s) differ from From domain")

        # suspicious words
        sk = feats.get("suspicious_keyword_count", 0)
        if sk > 0:
            score += sk * self.weights["suspicious_keywords"]
            reasons.append(f"{sk} suspicious keyword(s) found in subject/body")

        # attachments
        if feats.get("num_attachments", 0) > 0:
            score += self.weights["attachment"]
            reasons.append("Has attachment(s)")

        # final verdict
        verdict = "spoof" if score >= self.threshold else "legit"
        explanation = {
            "score": score,
            "threshold": self.threshold,
            "reasons": reasons,
            "features": feats,
            "protocol": proto,
            "parsed": {
                "subject": parsed.get("subject"),
                "from": parsed.get("from"),
                "from_domain": parsed.get("from_domain"),
                "urls": parsed.get("urls")[:10],
                "num_attachments": len(parsed.get("attachments", []))
            }
        }
        return {"verdict": verdict, "explanation": explanation}
