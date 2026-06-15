from __future__ import annotations

import re
from urllib.parse import urlparse
from typing import Optional


def domain_reputation_score(domain: str) -> float:
    # placeholder simple check; integrate blocked lists externally
    try:
        import socket
        socket.gethostbyname(domain)
        return 0.0
    except Exception:
        return 0.2


def domain_age_years(domain: str) -> Optional[float]:
    # whois optional; return None if not available
    try:
        import whois
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return None
        from datetime import datetime
        if isinstance(created, str):
            created = datetime.fromisoformat(created)
        delta = datetime.utcnow() - created
        return delta.days / 365.0
    except Exception:
        return None


def url_heuristic_score(url: str) -> float:
    try:
        parsed = urlparse(url)
    except Exception:
        return 0.0
    score = 0.0
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    suspicious_tokens = ["login", "secure", "update", "verify", "account", "bank", "confirm", "credential", "signin", "reset"]
    for t in suspicious_tokens:
        if t in url.lower():
            score += 0.15
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname):
        score += 0.2
    if hostname.count('.') >= 3:
        score += 0.1
    if len(path) > 40 or '-' in hostname:
        score += 0.1
    if '%' in url or '\\x' in url:
        score += 0.1
    try:
        rep = domain_reputation_score(hostname)
        score = min(1.0, score + rep * 0.5)
        age = domain_age_years(hostname)
        if age is not None and age < 1.0:
            score = min(1.0, score + 0.2)
    except Exception:
        pass
    return min(1.0, score)
