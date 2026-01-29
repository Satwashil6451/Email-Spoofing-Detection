# src/app.py

from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import JSONResponse, RedirectResponse
from typing import Optional, Tuple
import email
from email.utils import parseaddr
import dkim
import spf
import dns.resolver
import re

app = FastAPI(title="Email Spoofing Detection API",
              description="Detects potential spoofed
 emails using SPF, DKIM, and header checks",
              version="1.1.0")


def extract_email_address(from_header: str) -> Tuple[str, str]:
    """
    Returns (display_name, email_address) using email.utils.parseaddr.
    If email_address is empty, returns ("", "").
    """
    display, addr = parseaddr(from_header or "")
    return display, addr


def safe_check_dkim(raw_email: bytes) -> dict:
    """
    Returns {'status': 'pass'|'fail'|'none'|'error', 'detail': ...}
    dkim.verify returns True/False if signature present; if no signature, dkim.verify() raises.
    We handle exceptions and report 'none' when no signature is present.
    """

    try:
        valid = dkim.verify(raw_email)
        return {"status": "pass" if valid else "fail", "detail": None}
      
    except Exception as e:
        try:
            raw_str = raw_email.decode('utf-8', errors='ignore')
            if "DKIM-Signature:" in raw_str:
                return {"status": "fail", "detail": str(e)}
            else:
                return {"status": "none", "detail": "no DKIM-Signature header found"}
        except Exception:
            return {"status": "error", "detail": str(e)}


def safe_check_spf(sender_ip: Optional[str], envelope_from: Optional[str], helo: Optional[str]) -> dict:
  
    """
    Uses pyspf.check2 if sender_ip and envelope_from provided.
    Returns {'status': 'pass'|'fail'|'softfail'|'neutral'|'none'|'error', 'detail': ...}
    """
  
    if not sender_ip or not envelope_from:
        return {"status": "none", "detail": "missing sender_ip or envelope_from for SPF check"}
    try:
        result_tuple = spf.check2(i=sender_ip, s=envelope_from, h=helo or envelope_from)
        if isinstance(result_tuple, (list, tuple)) and len(result_tuple) >= 1:
            res = result_tuple[0]
            expl = result_tuple[1] if len(result_tuple) > 1 else ""
            return {"status": res, "detail": expl}
        else:
            return {"status": "error", "detail": f"unexpected spf result: {result_tuple}"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


def get_first_received_ip(msg: email.message.Message) -> Optional[str]:
    """
    Tries to parse the first Received header for an IPv4 address.

    This is a heuristic to suggest a sender_ip if user didn't provide one.
    """
    received_headers = msg.get_all("Received", [])
    if not received_headers:
        return None
    for header in reversed(received_headers):
        m = re.search(r"\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]", header)
        if m:
            return m.group(1)
        m2 = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})", header)
        if m2:
            return m2.group(1)
    return None

@app.get("/", include_in_schema=False)
def root_redirect():
    return RedirectResponse(url="/docs")

@app.post("/detect")
async def detect_spoofing(file: UploadFile = File(...),
                          sender_ip: Optional[str] = Form(None),
                          envelope_from: Optional[str] = Form(None),
                          helo: Optional[str] = Form(None)):
    """
    Upload a .eml file. Optionally provide:
      - sender_ip (the SMTP sending IP)
      - envelope_from (the MAIL FROM / bounce address)
      - helo (optional HELO/EHLO name)
    The endpoint will:
      - parse From header properly
      - run DKIM check (pass/fail/none)
      - run SPF if sender_ip & envelope_from provided
      - compute a friendly verdict with explanation
    """
    try:
        raw = await file.read()
        msg = email.message_from_bytes(raw)

        display_name, email_addr = extract_email_address(msg.get("From", ""))
        if not envelope_from:
            envelope_from = msg.get("Return-Path") or msg.get("Return-Path", "")
            envelope_from = envelope_from.strip().lstrip("<").rstrip(">") if envelope_from else None

        inferred_ip = get_first_received_ip(msg)
        used_sender_ip = sender_ip or inferred_ip

        dkim_res = safe_check_dkim(raw)
        spf_res = safe_check_spf(used_sender_ip, envelope_from or email_addr, helo)

        from_domain = email_addr.split("@")[-1] if email_addr and "@" in email_addr else ""
        msgid = msg.get("Message-ID", "")
        msgid_domain = ""
        if msgid and "@" in msgid:
            msgid_domain = msgid.split("@")[-1].strip(">").strip()

        return_path = msg.get("Return-Path", "") or ""
        _, return_path_addr = extract_email_address(return_path)
        return_path_domain = return_path_addr.split("@")[-1] if return_path_addr and "@" in return_path_addr else ""

        reasons = []
        score = 0.0

        if dkim_res["status"] == "pass":
            score -= 2.0
            reasons.append("DKIM passed (strong signal of authenticity).")
        elif dkim_res["status"] == "fail":
            score += 1.0
            reasons.append("DKIM present but failed verification.")
        else:
            reasons.append("No DKIM signature present (neutral).")

        if spf_res["status"] == "pass":
            score -= 2.0
            reasons.append("SPF passed (sending IP authorized).")
        elif spf_res["status"] in ("fail", "softfail"):
            score += 2.5
            reasons.append(f"SPF check: {spf_res['status']}.")
        elif spf_res["status"] == "none":
            reasons.append("SPF check not performed (missing info).")
        else:
            reasons.append(f"SPF check error or unknown: {spf_res.get('detail')}")

        if return_path_domain and from_domain and return_path_domain != from_domain:
            score += 1.5
            reasons.append(f"Return-Path domain ({return_path_domain}) differs from From domain ({from_domain}).")

        if msgid_domain and from_domain and msgid_domain != from_domain:
            score += 0.7
            reasons.append(f"Message-ID domain ({msgid_domain}) differs from From domain ({from_domain}).")

        subj = (msg.get("Subject") or "").lower()
      
        if any(k in subj for k in ["urgent", "verify", "update", "password", "confirm"]):
            score += 0.8
            reasons.append("Subject contains suspicious keywords (e.g., urgent/verify).")

        if not email_addr:
            score += 2.0
            reasons.append("No valid email address found in From header.")
        else:
            reasons.append(f"From address parsed as: {email_addr}")

        threshold = 1.5
        is_spoof = score >= threshold

        detail = {
            "parsed_from_display": display_name,
            "parsed_from_address": email_addr,
            "inferred_sender_ip": used_sender_ip,
            "dkim": dkim_res,
            "spf": spf_res,
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
            "message_id_domain": msgid_domain,
            "score": score,
            "threshold": threshold,
            "reasons": reasons
        }

        return JSONResponse({"verdict": "spoof" if is_spoof else "legit", "detail": detail})
    except Exception as e:
        return JSONResponse({"error": str(e)})
