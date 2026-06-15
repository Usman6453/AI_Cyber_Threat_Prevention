from __future__ import annotations

import re
from email import message_from_string
from typing import List

from .model import PhishingModelManager


URL_RE = re.compile(r"https?://[^\s'\">]+", flags=re.IGNORECASE)


def extract_links_from_email(raw_email: str) -> List[str]:
    try:
        msg = message_from_string(raw_email)
    except Exception:
        # fallback: search raw text
        return URL_RE.findall(raw_email)
    links: List[str] = []
    # scan headers
    for hdr in ("From", "Reply-To", "Subject"):
        val = msg.get(hdr)
        if val:
            links.extend(URL_RE.findall(val))
    # scan body
    if msg.is_multipart():
        for part in msg.walk():
            try:
                if part.get_content_type() == "text/plain":
                    text = part.get_payload(decode=True)
                    if isinstance(text, bytes):
                        text = text.decode(errors="ignore")
                    links.extend(URL_RE.findall(text or ""))
            except Exception:
                pass
    else:
        try:
            text = msg.get_payload(decode=True)
            if isinstance(text, bytes):
                text = text.decode(errors="ignore")
            links.extend(URL_RE.findall(text or ""))
        except Exception:
            pass
    # dedupe
    seen = set()
    out = []
    for u in links:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def scan_email(raw_email: str, model: PhishingModelManager) -> dict:
    links = extract_links_from_email(raw_email)
    results = []
    for link in links:
        pred = model.predict(link)
        results.append({"url": link, "label": pred.label, "confidence": pred.confidence, "risk": pred.risk})
    # also scan whole body
    body_pred = model.predict(raw_email)
    return {"links": results, "body": {"label": body_pred.label, "confidence": body_pred.confidence, "risk": body_pred.risk}}
