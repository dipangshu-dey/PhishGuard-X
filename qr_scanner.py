import logging
import cv2
import numpy as np
import re
from pathlib import Path
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
#  Known legitimate QR redirect platforms
# ──────────────────────────────────────────────────────────────
QR_PLATFORM_WHITELIST = [
    "scan.page",
    "qr.io",
    "qrco.de",
    "l.ead.me",
    "qr-code-generator.com",
    "me-qr.com",
    "qr.net",
    "qrfy.com",
    "flowcode.com",
    "beaconstac.com",
    "scncd.com",
    "rebrand.ly",
    "qr.codes",
    "uqr.me",
]


def _is_whitelisted_qr_platform(url: str) -> bool:
    try:
        hostname = urlparse(url).hostname or ""
        return any(hostname == d or hostname.endswith("." + d) for d in QR_PLATFORM_WHITELIST)
    except Exception:
        return False


# 🔥 NEW FIX — extract URL from noisy QR data
def _extract_url_from_text(text: str):
    match = re.search(r'https?://[^\s]+', text)
    return match.group(0) if match else None


def decode_qr(image_path: str) -> dict:

    result = {
        "success":  False,
        "url":      None,
        "raw_data": None,
        "qr_type":  "QRCODE",
        "error":    None,
    }

    path = Path(image_path)
    if not path.exists():
        result["error"] = f"File not found: {image_path}"
        logger.error(result["error"])
        return result

    try:
        img = cv2.imread(str(path))
        if img is None:
            result["error"] = f"Could not read image file: {image_path}"
            logger.error(result["error"])
            return result

        detector = cv2.QRCodeDetector()

        raw_data, points, _ = detector.detectAndDecode(img)

        if not raw_data:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            raw_data, points, _ = detector.detectAndDecode(gray)

        if not raw_data:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            raw_data, points, _ = detector.detectAndDecode(thresh)

        if not raw_data:
            try:
                wechat = cv2.wechat_qrcode_WeChatQRCode()
                texts, _ = wechat.detectAndDecode(img)
                if texts:
                    raw_data = texts[0]
            except Exception:
                pass

        if not raw_data:
            result["error"] = "No QR code found in the image."
            logger.warning(result["error"])
            return result

        raw_data = raw_data.strip()
        result["raw_data"] = raw_data

        # 🔥 MAIN FIX APPLIED HERE
        clean_url = _extract_url_from_text(raw_data)

        if clean_url:
            result["url"] = clean_url
            result["success"] = True
            logger.info(f"QR decoded — extracted URL: {clean_url}")

        elif raw_data.startswith("www."):
            result["url"] = "http://" + raw_data
            result["success"] = True
            logger.info(f"QR decoded — bare domain: {result['url']}")

        else:
            result["url"] = None
            result["success"] = True
            result["error"] = f"QR content is not a URL: {raw_data[:100]}"
            logger.info(f"QR decoded — non-URL content: {raw_data[:100]}")

    except Exception as e:
        result["error"] = f"QR decode error: {str(e)}"
        logger.error(result["error"])

    return result


def scan_qr_for_phishing(image_path: str):

    qr_result = decode_qr(image_path)

    if not qr_result["success"] or not qr_result["url"]:
        error_msg = qr_result.get("error", "QR decode failed")
        return {
            "input": image_path,
            "verdict": "UNKNOWN",
            "score": 0,
            "confidence": 0.0,
            "findings": [f"QR Scan Failed: {error_msg}"],
            "attack_type": "Unknown",
            "simulation": [],
            "impact": [],
            "recommendation": ["Provide a valid QR code image containing a URL"],
            "redirect_chain": [],
            "redirect_summary": "N/A",
            "campaign": {"message": "N/A"},
            "logs": [
                "[QR] Attempting to decode QR code...",
                f"[QR] Failed: {error_msg}",
            ],
            "domain_age_days": None,
            "domain_created": None,
            "qr_decoded_url": None,
            "qr_raw_data": qr_result.get("raw_data"),
        }

    extracted_url = qr_result["url"]

    # 🔥 existing whitelist logic untouched
    if _is_whitelisted_qr_platform(extracted_url):
        hostname = urlparse(extracted_url).hostname or extracted_url
        return {
            "input": f"[QR Code] {image_path}",
            "verdict": "SAFE",
            "score": 0,
            "confidence": 100.0,
            "findings": [f"Trusted QR Platform: {hostname}"],
            "attack_type": "None",
            "simulation": [],
            "impact": [],
            "recommendation": ["Safe — legitimate QR platform"],
            "redirect_chain": [],
            "redirect_summary": f"QR platform redirect ({hostname})",
            "campaign": {"message": "No campaign detected"},
            "logs": [
                f"[QR] Decoded URL: {extracted_url}",
                "[✓] SAFE (whitelisted QR platform)",
            ],
            "domain_age_days": None,
            "domain_created": "N/A",
            "qr_decoded_url": extracted_url,
            "qr_raw_data": qr_result.get("raw_data"),
        }

    from analyzer import analyze_url
    analysis = analyze_url(extracted_url)

    analysis["qr_decoded_url"] = extracted_url
    analysis["qr_raw_data"] = qr_result.get("raw_data")
    analysis["input"] = f"[QR Code] {image_path}"

    return analysis