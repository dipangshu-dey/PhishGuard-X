import re
import logging
import joblib
from datetime import datetime, timezone
from urllib.parse import urlparse

from feature_extractor import extract_features
from redirect_tracker import trace_redirects, summarize_chain
from campaign_detector import init_db, store_url, detect_campaign, DB_NAME as _CAMPAIGN_DB

# -------------------------------------------------- #
#  DB HELPERS
# -------------------------------------------------- #

def _update_verdict(url: str, verdict: str):
    """
    Updates the verdict for a URL that was already inserted by store_url().
    Used so the initial UNKNOWN placeholder is replaced with the final verdict
    after analysis completes, without creating a duplicate row.
    """
    import sqlite3 as _sqlite3
    try:
        conn = _sqlite3.connect(_CAMPAIGN_DB)
        c = conn.cursor()
        c.execute(
            "UPDATE urls SET verdict = ? WHERE url = ? AND verdict = 'UNKNOWN'",
            (verdict, url)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning("Could not update verdict in DB: %s", e)


# -------------------------------------------------- #

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "secure", "bank", "account",
    "login", "update", "password"
]

FINANCIAL_KEYWORDS  = ["payment", "bank", "money"]
CREDENTIAL_KEYWORDS = ["login", "password", "account", "verify"]

SHORTENERS = ["bit.ly", "tinyurl", "t.co"]

TRUSTED_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "stackoverflow.com",
    "youtube.com", "microsoft.com", "apple.com", "amazon.com",
    "twitter.com", "x.com", "linkedin.com", "reddit.com",
    "instagram.com", "facebook.com", "whatsapp.com"
]

QR_SAFE_INTERMEDIARIES = [
    "scan.page", "qr.io", "qrco.de", "l.ead.me",
    "qr-code-generator.com", "me-qr.com", "qr.net",
    "qrfy.com", "flowcode.com", "beaconstac.com",
    "scncd.com", "rebrand.ly"
]

BLOCKED_SCHEMES = ["javascript:", "data:", "vbscript:", "file:"]

REDIRECT_WEIGHTS = {"ALERT": 25, "SUSPICIOUS": 15, "WARNING": 10}

PHISHING_THRESHOLD   = 70
SUSPICIOUS_THRESHOLD = 30

RULE_WEIGHT = 0.4
ML_WEIGHT   = 0.6

MAX_REDIRECT_SCORE = 30

# Domain age thresholds (days)
WHOIS_NEW_DOMAIN_DAYS    = 30    # under 30 days  → very suspicious (+30)
WHOIS_RECENT_DOMAIN_DAYS = 180   # under 180 days → suspicious (+15)

# -------------------------------------------------- #
#  STRENGTHENED RULE SIGNALS
# -------------------------------------------------- #

IMPERSONATED_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "twitter", "whatsapp", "linkedin",
    "ebay", "dropbox", "chase", "wellsfargo", "citibank", "hsbc",
    "barclays", "halifax", "santander", "dhl", "fedex", "ups",
    "steam", "discord", "roblox", "yahoo", "outlook", "office365",
    "docusign", "coinbase", "binance", "blockchain"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".click", ".link", ".online", ".site", ".club", ".icu",
    ".buzz", ".fun", ".rest", ".live", ".work", ".space",
    ".shop", ".store", ".info", ".biz", ".pw", ".cc"
]

FAKE_DOMAIN_PATTERNS = [
    re.compile(r"(?:[a-z0-9]+-){3,}[a-z0-9]+\.[a-z]{2,}"),
    re.compile(r"(paypal|apple|microsoft|google|amazon|netflix|facebook|ebay|chase|hsbc|barclays)"
               r"\.[a-z0-9\-]+\.[a-z]{2,}"),
    re.compile(r"(?:[a-z0-9\-]{50,})\.[a-z]{2,}"),
]

# -------------------------------------------------- #
#  CONTENT ANALYSIS SIGNALS
# -------------------------------------------------- #

CONTENT_PHISHING_KEYWORDS = [
    "urgent", "verify", "login", "password", "account", "bank",
    "update", "secure", "suspended", "confirm", "validate",
    "reactivate", "restricted", "blocked", "compromised"
]

CONTENT_PRESSURE_PHRASES = [
    "immediately", "within 24 hours", "within 24hrs", "action required",
    "limited time", "expires soon", "act now", "respond immediately",
    "your account will be", "failure to respond", "last chance",
    "final notice", "account suspended", "access revoked"
]

CONTENT_IMPERSONATION_TERMS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "your bank", "dear customer",
    "dear user", "dear account holder", "support team",
    "security team", "it department", "helpdesk"
]

CONTENT_CTA_PHRASES = [
    "click here", "verify now", "login now", "confirm now",
    "click the link", "click below", "sign in now",
    "update your information", "verify your identity",
    "complete verification", "reset your password",
    "follow the link", "tap here", "open the link"
]

# -------------------------------------------------- #
#  LOOKUP TABLES
# -------------------------------------------------- #

SIMULATIONS = {
    "Credential Harvesting": [
        "User clicks phishing link",
        "Fake login page displayed",
        "User enters credentials",
        "Credentials sent to attacker",
    ],
    "Financial Scam": [
        "User redirected to fake payment page",
        "User enters card details",
        "Money deducted",
    ],
    "Brand Impersonation": [
        "User receives message appearing to be from trusted brand",
        "User clicks embedded link or follows instructions",
        "User provides sensitive information",
        "Data harvested by attacker",
    ],
}

IMPACTS = {
    "Credential Harvesting": ["Account compromise", "Data theft"],
    "Financial Scam":        ["Financial loss"],
    "Brand Impersonation":   ["Identity theft", "Account takeover"],
}

RECOMMENDATIONS = {
    "PHISHING":   ["Do not open link", "Report immediately", "Change passwords"],
    "SUSPICIOUS": ["Verify source before interacting"],
    "SAFE":       ["No action required"],
}


# -------------------------------------------------- #
#  MODULE-LEVEL SINGLETON
# -------------------------------------------------- #

_analyzer_instance = None


def _get_analyzer() -> "ThreatAnalyzer":
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = ThreatAnalyzer()
    return _analyzer_instance


# -------------------------------------------------- #
#  HELPERS
# -------------------------------------------------- #

def _parse_hostname(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _is_hex_encoded(url: str) -> bool:
    return bool(re.search(r"%[0-9a-fA-F]{2}", url))


def _sanitize_input(raw: str) -> tuple:
    url = raw.strip()
    if not url:
        return "", "Empty input provided"
    url_lower = url.lower()
    for scheme in BLOCKED_SCHEMES:
        if url_lower.startswith(scheme):
            return url, f"Blocked scheme detected: {scheme}"
    if not url_lower.startswith("http"):
        logger.warning("Input has no http/https scheme, proceeding anyway: %s", url)
    return url, None


def _is_qr_safe_intermediary(url: str) -> bool:
    """
    Returns True if the URL belongs to a known legitimate QR redirect platform.
    These should never be penalised in the scoring pipeline.
    """
    hostname = _parse_hostname(url)
    return any(
        hostname == d or hostname.endswith("." + d)
        for d in QR_SAFE_INTERMEDIARIES
    )


# -------------------------------------------------- #
#  WHOIS DOMAIN AGE CHECKER
# -------------------------------------------------- #

def check_domain_age(url: str, logs: list) -> tuple:
    """
    Looks up WHOIS registration date of the domain.
    Returns (findings, whois_score, age_days, created_date_str).

    < 30 days  → +30 score (Very New Domain — HIGH RISK)
    < 180 days → +15 score (Recently Registered)
    older      → +0        (OK)
    """
    findings    = []
    whois_score = 0
    age_days    = None
    created_str = "Unknown"

    try:
        import whois
        hostname = _parse_hostname(url)

        if not hostname or re.match(r"\d+\.\d+\.\d+\.\d+", hostname):
            logs.append("[WHOIS] Skipped — IP address or no hostname")
            return findings, 0, None, "N/A"

        logs.append(f"[WHOIS] Looking up: {hostname}")
        w = whois.whois(hostname)

        creation = w.creation_date

        # ── FIX: handle list — pick first valid datetime ──
        if isinstance(creation, list):
            creation = next(
                (d for d in creation if d is not None),
                None
            )

        # ── FIX: handle string fallback ──
        if isinstance(creation, str):
            try:
                creation = datetime.strptime(creation[:10], "%Y-%m-%d")
            except ValueError:
                creation = None

        # ── FIX: convert timezone-aware datetime to UTC first, then strip tzinfo ──
        if creation is not None and hasattr(creation, "tzinfo") and creation.tzinfo is not None:
            creation = creation.astimezone(timezone.utc).replace(tzinfo=None)

        if creation is not None:
            age_days    = (datetime.utcnow() - creation).days
            created_str = creation.strftime("%Y-%m-%d")

            if age_days < WHOIS_NEW_DOMAIN_DAYS:
                findings.append(f"Very New Domain — Registered only {age_days} days ago (HIGH RISK)")
                whois_score = 30
                logs.append(f"[WHOIS] Age: {age_days} days — VERY NEW DOMAIN (+30 risk)")

            elif age_days < WHOIS_RECENT_DOMAIN_DAYS:
                findings.append(f"Recently Registered Domain — {age_days} days old (SUSPICIOUS)")
                whois_score = 15
                logs.append(f"[WHOIS] Age: {age_days} days — RECENT DOMAIN (+15 risk)")

            else:
                logs.append(f"[WHOIS] Age: {age_days} days — established domain, OK")
        else:
            logs.append("[WHOIS] Creation date unavailable or could not be parsed")

    except ImportError:
        logs.append("[WHOIS] python-whois not installed — run: pip install python-whois")
    except Exception as e:
        logs.append(f"[WHOIS] Lookup failed: {str(e)[:80]}")

    return findings, whois_score, age_days, created_str


# -------------------------------------------------- #
#  MAIN CLASS
# -------------------------------------------------- #

class ThreatAnalyzer:

    def __init__(self):
        self.ml_model = self._load_model()
        init_db()

    def _load_model(self):
        try:
            model = joblib.load("url_model.pkl")
            logger.info("ML model loaded successfully.")
            return model
        except FileNotFoundError:
            logger.warning("url_model.pkl not found — rule-based scoring only.")
        except Exception as e:
            logger.warning("ML model could not be loaded: %s", e)
        return None

    def _is_trusted(self, url: str) -> bool:
        hostname = _parse_hostname(url)
        return any(
            hostname == d or hostname.endswith("." + d)
            for d in TRUSTED_DOMAINS
        )

    def _rule_analysis(self, url: str):
        findings  = []
        score     = 0
        url_lower = url.lower()
        hostname  = _parse_hostname(url_lower)

        if any(w in url_lower for w in SUSPICIOUS_KEYWORDS):
            findings.append("Suspicious Keywords Detected")
            score += 10

        if not url_lower.startswith("https"):
            findings.append("Missing HTTPS")
            score += 10

        if re.search(r"\d{1,3}(\.\d{1,3}){3}", url_lower):
            findings.append("IP Address Used")
            score += 20

        if hostname.count(".") > 3:
            findings.append("Too Many Subdomains")
            score += 10

        if len(url) > 75:
            findings.append("Long URL Detected")
            score += 10

        if "%" in url and _is_hex_encoded(url):
            findings.append("Encoded URL Detected")
            score += 15

        if any(s in url_lower for s in SHORTENERS):
            findings.append("URL Shortener Detected")
            score += 15

        detected_brands = [b for b in IMPERSONATED_BRANDS if b in url_lower]
        if detected_brands:
            is_real_brand = any(
                hostname == f"{b}.com" or hostname.endswith(f".{b}.com")
                for b in detected_brands
            )
            if not is_real_brand:
                findings.append(f"Brand Impersonation Detected: {', '.join(detected_brands)}")
                score += 30

        matched_tld = next((tld for tld in SUSPICIOUS_TLDS if hostname.endswith(tld)), None)
        if matched_tld:
            findings.append(f"Suspicious TLD Detected: {matched_tld}")
            score += 20

        for pattern in FAKE_DOMAIN_PATTERNS:
            if pattern.search(hostname):
                findings.append("Fake Domain Pattern Detected")
                score += 20
                break

        return findings, min(score, 100)

    def _content_analysis(self, text: str):
        findings   = []
        score      = 0
        text_lower = text.lower()

        matched_keywords = [w for w in CONTENT_PHISHING_KEYWORDS if w in text_lower]
        if matched_keywords:
            findings.append("Phishing Language Detected")
            score += min(5 + len(matched_keywords) * 2, 12)

        matched_pressure = [p for p in CONTENT_PRESSURE_PHRASES if p in text_lower]
        if matched_pressure:
            findings.append("Urgency Pressure Detected")
            score += min(4 + len(matched_pressure) * 2, 10)

        matched_impersonation = [t for t in CONTENT_IMPERSONATION_TERMS if t in text_lower]
        if matched_impersonation:
            findings.append("Impersonation Detected")
            score += min(4 + len(matched_impersonation) * 2, 10)

        matched_cta = [c for c in CONTENT_CTA_PHRASES if c in text_lower]
        if matched_cta:
            findings.append("Suspicious Call-to-Action Detected")
            score += min(3 + len(matched_cta) * 2, 8)

        return findings, min(score, 30)

    def _ml_analysis(self, url: str, logs: list):
        if not self.ml_model:
            return 0, None
        try:
            features   = extract_features(url)
            pred       = self.ml_model.predict([features])[0]
            proba      = self.ml_model.predict_proba([features])[0]
            confidence = round(float(max(proba)) * 100, 2)
            if pred == 1:
                logs.append(f"[ML] PHISHING ({confidence}%)")
                return 60, confidence
            logs.append(f"[ML] SAFE ({confidence}%)")
            return 0, confidence
        except Exception as e:
            logs.append(f"[ML ERROR] {e}")
            return 0, None

    def _detect_attack_type(self, url: str) -> str:
        url_lower = url.lower()
        if "%" in url_lower and _is_hex_encoded(url_lower):
            return "Obfuscated Link"
        if any(s in url_lower for s in SHORTENERS):
            return "Shortened Link"
        if re.search(r"\d{1,3}(\.\d{1,3}){3}", url_lower):
            return "URL Spoofing"
        if any(k in url_lower for k in FINANCIAL_KEYWORDS):
            return "Financial Scam"
        if any(k in url_lower for k in CREDENTIAL_KEYWORDS):
            return "Credential Harvesting"
        if any(brand in url_lower for brand in IMPERSONATED_BRANDS):
            return "Brand Impersonation"
        return "Unknown"

    def _simulate(self, attack_type: str) -> list:
        return SIMULATIONS.get(attack_type, ["Basic phishing behavior"])

    def _impact(self, attack_type: str) -> list:
        return IMPACTS.get(attack_type, ["General risk"])

    def _recommend(self, verdict: str) -> list:
        return RECOMMENDATIONS.get(verdict, ["No action required"])

    def _redirect_score(self, chain: list) -> int:
        score = 0
        for hop in chain:
            cls = hop.get("classification", "").upper()
            if _is_qr_safe_intermediary(hop.get("url", "")):
                continue
            for label, weight in REDIRECT_WEIGHTS.items():
                if label in cls:
                    score += weight
                    break
        if len(chain) > 3:
            score += 10
        return min(score, MAX_REDIRECT_SCORE)

    def _get_verdict(self, score: int) -> str:
        if score >= PHISHING_THRESHOLD:
            return "PHISHING"
        if score >= SUSPICIOUS_THRESHOLD:
            return "SUSPICIOUS"
        return "SAFE"

    def _build_response(self, url, verdict, score, confidence, findings,
                        attack, simulation, impact, recommendation,
                        chain, summary, campaign, logs,
                        domain_age_days=None, domain_created=None) -> dict:
        return {
            "url":              url,
            "input":            url,
            "verdict":          verdict,
            "score":            score,
            "confidence":       confidence if confidence is not None else 0.0,
            "findings":         findings,
            "attack_type":      attack,
            "simulation":       simulation,
            "impact":           impact,
            "recommendation":   recommendation,
            "redirect_chain":   chain,
            "redirect_summary": summary,
            "campaign":         campaign,
            "logs":             logs,
            "domain_age_days":  domain_age_days,
            "domain_created":   domain_created,
        }

    def analyze_hybrid(self, input_data: str, content_text: str = "") -> dict:
        logs = []

        # Step 0 — Sanitize
        url, error = _sanitize_input(str(input_data))
        if error:
            logs.append(f"[!] Input Error: {error}")
            return self._build_response(
                url, "UNKNOWN", 0, 0.0, [error],
                "Unknown", [], [], ["Provide a valid URL"],
                [], "No redirects", {"message": "N/A"}, logs
            )

        logs.append("[+] Analysis Started")

        # Step 1 — Redirect chain
        try:
            redirect_chain = trace_redirects(url)
            summary        = summarize_chain(redirect_chain)
        except Exception as e:
            redirect_chain, summary = [], "Redirect tracking unavailable"
        logs.append(f"[✓] Redirect Chain: {summary}")

        # FIX 3: store_url FIRST so the current URL is already in the DB
        # when detect_campaign runs its COUNT query.
        try:
            store_url(url, verdict="UNKNOWN")
            logs.append("[DB] URL stored successfully")
        except Exception as e:
            logs.append(f"[DB ERROR] {e}")
            raise e

        # Step 2 — Campaign detection (runs AFTER the insert above)
        try:
            campaign = detect_campaign(url)
            logs.append(f"[✓] {campaign.get('message', 'Campaign check complete')}")
        except Exception as e:
            campaign = {"message": "Campaign detection unavailable"}

        # Resolve the final destination from the redirect chain
        final_destination = redirect_chain[-1].get("url", url) if redirect_chain else url
        final_hostname    = _parse_hostname(final_destination)

        # Trusted domain fast-path checks BOTH the input URL AND the final redirect destination
        if self._is_trusted(url) or self._is_trusted(final_destination):
            logs.append(f"[✓] Trusted domain (resolved final: {final_destination}) — SAFE")
            try:
                _update_verdict(url, verdict="SAFE")
            except Exception:
                pass
            return self._build_response(
                url, "SAFE", 0, 0.0, ["Trusted Domain"],
                "None", [], [], ["Safe"],
                redirect_chain, summary, campaign, logs
            )

        # If the URL itself is a known QR intermediary, analyse the FINAL destination instead
        url_to_analyse = url
        if _is_qr_safe_intermediary(url) and final_destination and final_destination != url:
            logs.append(f"[QR] Known QR intermediary detected ({_parse_hostname(url)}) — "
                        f"analysing final destination: {final_destination}")
            url_to_analyse = final_destination

            # Re-run trusted check on the resolved destination
            if self._is_trusted(url_to_analyse):
                logs.append(f"[✓] Final destination is trusted — SAFE")
                try:
                    _update_verdict(url, verdict="SAFE")
                except Exception:
                    pass
                return self._build_response(
                    url, "SAFE", 0, 0.0, ["Trusted Domain (via QR redirect)"],
                    "None", [], [], ["Safe"],
                    redirect_chain, summary, campaign, logs
                )

        # Step 4 — Rule-based scoring (on the resolved URL)
        findings, rule_score = self._rule_analysis(url_to_analyse)
        logs.append(f"[Rules] Score: {rule_score} | Findings: {len(findings)}")

        # Step 5 — Redirect risk (QR-safe hops are skipped inside _redirect_score)
        r_score = self._redirect_score(redirect_chain)
        if r_score > 0:
            findings.append(f"Redirect Risk (+{r_score})")
            logs.append(f"[Redirects] +{r_score} risk added")

        # Step 6 — Content analysis
        content_score = 0
        if content_text and content_text.strip():
            content_findings, content_score = self._content_analysis(content_text)
            findings.extend(content_findings)
            if content_score > 0:
                logs.append(f"[Content] Score: {content_score} | Findings: {len(content_findings)}")
        else:
            logs.append("[Content] No text body provided — skipped")

        # Step 7 — ML prediction (on the resolved URL)
        ml_score, confidence = self._ml_analysis(url_to_analyse, logs)

        # Step 8 — WHOIS domain age (on the resolved URL)
        whois_findings, whois_score, age_days, created_str = check_domain_age(url_to_analyse, logs)
        findings.extend(whois_findings)

        # Step 9 — Hybrid final score
        final_score = min(
            round(
                (rule_score    * RULE_WEIGHT) +
                (r_score       * RULE_WEIGHT) +
                (content_score * RULE_WEIGHT) +
                (whois_score   * RULE_WEIGHT) +
                (ml_score      * ML_WEIGHT)
            ),
            100
        )
        verdict = self._get_verdict(final_score)
        logs.append(f"[✓] Final Score: {final_score} → {verdict}")

        # Step 10 — Update verdict now that we have the final score
        try:
            _update_verdict(url, verdict=verdict)
        except Exception:
            pass

        # Step 11 — Attack metadata
        attack = self._detect_attack_type(url_to_analyse)
        logs.append("[✓] Analysis Completed")

        return self._build_response(
            url, verdict, final_score, confidence, findings,
            attack, self._simulate(attack), self._impact(attack),
            self._recommend(verdict),
            redirect_chain, summary, campaign, logs,
            domain_age_days=age_days,
            domain_created=created_str
        )


# -------------------------------------------------- #
#  PUBLIC INTERFACES
# -------------------------------------------------- #

def analyze_url(url: str) -> dict:
    return _get_analyzer().analyze_hybrid(url)


# -------------------------------------------------- #
#  FIXED: Email / SMS / File — placeholder URL when no URL found
# -------------------------------------------------- #

def analyze_email(email_text: str) -> dict:
    urls = re.findall(r'https?://\S+', email_text)
    url  = urls[0] if urls else "email-input"
    return _get_analyzer().analyze_hybrid(url, content_text=email_text)


def analyze_sms(sms_text: str) -> dict:
    urls = re.findall(r'https?://\S+', sms_text)
    url  = urls[0] if urls else "sms-input"
    return _get_analyzer().analyze_hybrid(url, content_text=sms_text)


def analyze_file(file_path: str) -> dict:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        content = str(file_path)
    urls = re.findall(r'https?://\S+', content)
    url  = urls[0] if urls else "file-input"
    return _get_analyzer().analyze_hybrid(url, content_text=content)