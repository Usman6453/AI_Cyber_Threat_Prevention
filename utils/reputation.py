from __future__ import annotations

from datetime import datetime
from pathlib import Path
import socket
import logging

try:
    import whois
except Exception:
    whois = None

from config.settings import BLOCKLIST_DIR

LOG = logging.getLogger(__name__)


def domain_reputation_score(domain: str) -> float:
    """Return a simple reputation score 0.0-1.0 for a domain.

    - 0.0 means unknown/benign
    - higher values indicate more suspicious (1.0 max)
    Uses a local blocklist file if present; otherwise attempts DNS resolution.
    """
    try:
        blk = BLOCKLIST_DIR / "blacklisted_domains.txt"
        if blk.exists():
            txt = blk.read_text(encoding="utf-8")
            if domain in txt.splitlines():
                return 1.0
    except Exception:
        pass
    # quick DNS check: if domain doesn't resolve, slightly suspicious
    try:
        socket.gethostbyname(domain)
        dns_ok = True
    except Exception:
        dns_ok = False
    return 0.0 if dns_ok else 0.2


def domain_age_years(domain: str) -> float | None:
    """Try to get domain creation date using whois; return age in years or None."""
    if whois is None:
        LOG.debug("whois library not available; skipping domain age check")
        return None
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return None
        if isinstance(created, str):
            created = datetime.fromisoformat(created)
        delta = datetime.utcnow() - created
        return delta.days / 365.0
    except Exception:
        return None
