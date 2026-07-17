import sqlite3
import logging
import os
from datetime import datetime
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

# FIX 1: Use absolute path so ALL modules (analyzer, dashboard, campaign_detector)
# always open the SAME database file regardless of which directory they run from.
DB_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "campaigns.db")

# How many URLs from the same domain before we call it a campaign
CAMPAIGN_THRESHOLD = 3


def init_db():
    """
    Creates the URL tracking table if it doesn't exist.
    Also stores verdict and timestamp so campaign reports are meaningful.
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS urls (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                domain    TEXT NOT NULL,
                url       TEXT NOT NULL,
                verdict   TEXT DEFAULT 'UNKNOWN',
                timestamp TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()
        logging.info("Campaign database initialized.")
    except Exception as e:
        logging.error(f"Failed to initialize campaign database: {e}")


def store_url(url: str, verdict: str = "UNKNOWN"):
    """
    Stores a URL and its verdict in the campaign database.
    Includes a timestamp so you can show when each URL was seen.
    Skips storing if the exact same URL was already recorded — prevents duplicates.
    """
    try:
        domain = urlparse(url).netloc
        if not domain:
            logging.warning(f"Could not extract domain from URL: {url}")
            return

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        # Avoid duplicate entries for the same URL
        c.execute("SELECT COUNT(*) FROM urls WHERE url = ?", (url,))
        already_exists = c.fetchone()[0] > 0

        if not already_exists:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute(
                "INSERT INTO urls (domain, url, verdict, timestamp) VALUES (?, ?, ?, ?)",
                (domain, url, verdict, timestamp)
            )
            conn.commit()
            logging.info(f"URL stored: {domain} | {verdict}")
        else:
            logging.info(f"URL already in database, skipping: {url}")

        conn.close()

    except Exception as e:
        logging.error(f"Failed to store URL in campaign database: {e}")


def detect_campaign(url: str) -> dict:
    """
    Checks if the domain of the given URL has appeared multiple times.
    Returns a structured dict so the report and GUI can render it properly.

    IMPORTANT: Call store_url() BEFORE calling detect_campaign() so the current
    URL is already counted when the threshold check runs.

    If the same domain appears 3+ times across different URLs,
    it's flagged as a coordinated phishing campaign.
    """
    try:
        domain = urlparse(url).netloc
        if not domain:
            return {
                "campaign_detected": False,
                "domain": "unknown",
                "count": 0,
                "message": "Could not extract domain for campaign check."
            }

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        # Total times this domain has been seen
        c.execute("SELECT COUNT(*) FROM urls WHERE domain = ?", (domain,))
        count = c.fetchone()[0]

        # Pull the last 5 seen URLs from this domain for the report
        c.execute(
            "SELECT url, verdict, timestamp FROM urls WHERE domain = ? ORDER BY id DESC LIMIT 5",
            (domain,)
        )
        recent_urls = [
            {"url": row[0], "verdict": row[1], "timestamp": row[2]}
            for row in c.fetchall()
        ]

        conn.close()

        if count >= CAMPAIGN_THRESHOLD:
            return {
                "campaign_detected": True,
                "domain": domain,
                "count": count,
                "recent_urls": recent_urls,
                "message": f"Campaign Detected: {count} URLs observed from '{domain}'"
            }

        return {
            "campaign_detected": False,
            "domain": domain,
            "count": count,
            "recent_urls": recent_urls,
            "message": f"No campaign detected ({count} URL(s) seen from '{domain}')"
        }

    except Exception as e:
        logging.error(f"Campaign detection error: {e}")
        return {
            "campaign_detected": False,
            "domain": "error",
            "count": 0,
            "message": f"Campaign detection failed: {str(e)}"
        }


def get_all_campaigns() -> list:
    """
    Returns all domains that have crossed the campaign threshold.
    Useful for a dashboard view showing active phishing campaigns.
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("""
            SELECT domain, COUNT(*) as total
            FROM urls
            GROUP BY domain
            HAVING total >= ?
            ORDER BY total DESC
        """, (CAMPAIGN_THRESHOLD,))

        campaigns = [
            {"domain": row[0], "url_count": row[1]}
            for row in c.fetchall()
        ]
        conn.close()
        return campaigns

    except Exception as e:
        logging.error(f"Failed to retrieve campaigns: {e}")
        return []