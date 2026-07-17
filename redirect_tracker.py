import logging
import requests
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

# Domains known to be used as redirect intermediaries in phishing chains
SUSPICIOUS_REDIRECT_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "rebrand.ly", "cutt.ly", "short.io"
]

# How many redirects we allow before we stop following — prevents infinite loops
MAX_HOPS = 10


def _classify_hop(url: str) -> str:
    """
    Tags each hop in the redirect chain with a risk label.
    Helps the report show which step in the chain is suspicious.
    """
    try:
        hostname = urlparse(url).hostname or ""
        if any(domain in hostname for domain in SUSPICIOUS_REDIRECT_DOMAINS):
            return "SUSPICIOUS — Known URL Shortener"
        if not url.startswith("https"):
            return "WARNING — Unencrypted Hop"
        return "OK"
    except Exception:
        return "UNKNOWN"


def trace_redirects(url: str) -> list:
    """
    Follows a URL through its full redirect chain and logs every hop.
    Returns a list of dicts with url, status code, and risk classification.

    Uses a capped redirect limit to prevent redirect loop abuse.
    A separate session is used so we can control max_redirects precisely.
    """
    hops = []

    session = requests.Session()
    session.max_redirects = MAX_HOPS

    try:
        response = session.get(
    url,
    allow_redirects=True,
    timeout=10,
    verify=False,
    headers={
        "User-Agent": "Mozilla/5.0"
    }
)

        # Log every intermediate redirect hop
        for r in response.history:
            hop_entry = {
                "url": r.url,
                "status": r.status_code,
                "classification": _classify_hop(r.url)
            }
            hops.append(hop_entry)
            logging.info(f"[Redirect Hop] {r.status_code} → {r.url}")

        # Log final destination
        final_entry = {
            "url": response.url,
            "status": response.status_code,
            "classification": _classify_hop(response.url),
            "final_destination": True
        }
        hops.append(final_entry)
        logging.info(f"[Final Destination] {response.status_code} → {response.url}")

    except requests.exceptions.TooManyRedirects:
        logging.warning(f"Redirect loop detected for: {url}")
        hops.append({
            "url": url,
            "status": None,
            "classification": "ALERT — Redirect Loop Detected",
            "error": "Too many redirects — possible evasion technique"
        })

    except requests.exceptions.ConnectionError:
        logging.warning(f"Could not connect to: {url}")
        hops.append({
            "url": url,
            "status": None,
            "classification": "UNREACHABLE",
            "error": "Connection failed — domain may be down or blocking scanners"
        })

    except requests.exceptions.Timeout:
        logging.warning(f"Timeout while tracing: {url}")
        hops.append({
            "url": url,
            "status": None,
            "classification": "TIMEOUT",
            "error": "Request timed out — server did not respond"
        })

    except Exception as e:
        logging.error(f"Redirect trace error: {e}")
        hops.append({
            "url": url,
            "status": None,
            "classification": "ERROR",
            "error": str(e)
        })

    return hops


def summarize_chain(hops: list) -> str:
    """
    Returns a one-line summary of the redirect chain for the GUI console log.
    Example: '3 hops — 1 suspicious intermediary — Final: https://evil.com'
    """
    if not hops:
        return "No redirect data available."

    total = len(hops)
    suspicious = sum(1 for h in hops if "SUSPICIOUS" in h.get("classification", "") or "WARNING" in h.get("classification", ""))
    final = hops[-1].get("url", "Unknown")

    return f"{total} hop(s) traced — {suspicious} suspicious — Final destination: {final}"
