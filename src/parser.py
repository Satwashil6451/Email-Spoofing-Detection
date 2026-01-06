# src/parser.py

from email import policy
from email import message_from_bytes
from email.utils import parseaddr
from bs4 import BeautifulSoup
import re
from typing import Dict, Any, List

URL_REGEX = re.compile(r"https?://[^\s\"'<>]+")

def _extract_text_and_html(msg):
    text_parts = []
    html_parts = []
    for part in msg.walk():
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        if ctype == "text/plain" and disp != "attachment":
            try:
                text_parts.append(part.get_content())
            except Exception:
                text_parts.append(part.get_payload(decode=True) or "")
        elif ctype == "text/html" and disp != "attachment":
            try:
                html_parts.append(part.get_content())
            except Exception:
                html_parts.append(part.get_payload(decode=True) or "")
    text = "\n".join(filter(None, [str(x) for x in text_parts])).strip()
    html = "\n".join(filter(None, [str(x) for x in html_parts])).strip()
    
    if not text and html:
        text = BeautifulSoup(html, "html.parser").get_text(separator="\n")
    return text, html

def extract_urls(text: str) -> List[str]:
    return URL_REGEX.findall(text or "")

def get_domain_from_email(addr: str) -> str:
    if not addr:
        return ""
    addr = addr.strip()
    # parseaddr gives (name, email)
    _, email_addr = parseaddr(addr)
    parts = email_addr.split("@")
    return parts[1].lower() if len(parts) == 2 else ""

def parse_email(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Returns:
      {
        'headers': dict,
        'subject': str,
        'from': str,
        'from_domain': str,
        'return_path': str,
        'message_id': str,
        'received': [list of Received headers],
        'text': str,
        'html': str,
        'urls': [list],
        'attachments': [{'filename', 'content_type', 'size'}]
      }
    """
    
    msg = message_from_bytes(raw_bytes, policy=policy.default)
    headers = dict(msg.items())
    subj = headers.get("Subject", "")
    from_hdr = headers.get("From", "")
    return_path = headers.get("Return-Path", "")
    message_id = headers.get("Message-ID", "")
    received = [v for k, v in msg.items() if k.lower() == "received"]

    text, html = _extract_text_and_html(msg)
    urls = []
    urls.extend(extract_urls(text))
    urls.extend(extract_urls(html))

    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            attachments.append({
                "filename": part.get_filename(),
                "content_type": part.get_content_type(),
                "size": len(part.get_payload(decode=True) or b"")
            })

    return {
        "headers": headers,
        "subject": subj,
        "from": from_hdr,
        "from_domain": get_domain_from_email(from_hdr),
        "return_path": return_path,
        "return_path_domain": get_domain_from_email(return_path),
        "message_id": message_id,
        "message_id_domain": get_domain_from_email(message_id),
        "received": received,
        "text": text,
        "html": html,
        "urls": list(set(urls)),
        "attachments": attachments
    }
