# src/protocol_checks.py

import dkim
import spf
import dns.resolver
from typing import Optional, Dict

def check_dkim(raw_bytes: bytes) -> Dict[str, object]:
    """
    Returns {'dkim_valid': bool, 'error': str|None}
    """
    
    try:
        valid = dkim.verify(raw_bytes)
        return {"dkim_valid": bool(valid), "error": None}
    except Exception as e:
        return {"dkim_valid": False, "error": str(e)}

def check_spf(sender_ip: Optional[str], envelope_from: Optional[str], helo: Optional[str]) -> Dict[str, object]:
    
    """
    Requires sending IP (sender_ip) and envelope-from (MAIL FROM).
    Uses pyspf.check2 which returns (result, explanation)
    result: 'pass', 'fail', 'softfail', 'neutral', etc.
    """
    
    if not sender_ip or not envelope_from:
        return {"spf_result": "none", "spf_explain": "missing sender_ip or envelope_from"}
        
    try:
        res = spf.check2(i=sender_ip, s=envelope_from, h=helo or envelope_from)
        # spf.check2 returns a tuple (result, explanation)
        result, explanation = res[0], res[1]
        return {"spf_result": result, "spf_explain": explanation}
    except Exception as e:
        return {"spf_result": "error", "spf_explain": str(e)}

def get_dmarc(domain: str) -> Dict[str, Optional[str]]:
    """
    Query _dmarc.domain TXT record. Returns {'dmarc': txt or None, 'policy': 'none'|'quarantine'|'reject'|None}
    """
    if not domain:
        return {"dmarc": None, "policy": None}
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        txts = []
        for r in answers:
            # r.strings may be list of bytes or str
            if hasattr(r, "strings"):e
                joined = b"".join(r.strings).decode(errors="ignore") if isinstance(r.strings[0], (bytes, bytearray)) else "".join(r.strings)
            else:
                joined = str(r)
            txts.append(joined)
        txt = " ".join(txts)
        
        # try to find p=...
        policy = None
        if "p=" in txt:
            # simple parse
            parts = txt.split(";")
            for p in parts:
                if "p=" in p:
                    policy = p.strip().split("=")[1]
                    break
        return {"dmarc": txt, "policy": policy}
    except Exception:
        return {"dmarc": None, "policy": None}
