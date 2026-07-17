import re
from urllib.parse import urlparse
from typing import List

def extract_features(url: str) -> List[int]:
    """
    Parses a URL and extracts numerical features for the ML model.
    These features represent common obfuscation techniques used in phishing.
    """
    features = []
    
    try:
        # Ensure URL can be parsed correctly even if missing HTTP
        if not url.startswith(('http://', 'https://')):
            parsed_url = f"http://{url}"
        else:
            parsed_url = url
            
        parsed = urlparse(parsed_url)
        domain = parsed.netloc

        # 1. URL Length: Phishers often use very long URLs to hide the actual domain
        features.append(len(url))

        # 2. Subdomain Count: Legitimate sites rarely have more than 3 subdomains (e.g., login.mail.domain.com)
        features.append(url.count("."))

        # 3. Hyphen Count: Brand spoofing often uses hyphens (e.g., secure-update-apple.com)
        features.append(url.count("-"))

        # 4. Encryption (HTTPS): Simple binary check for SSL/TLS
        features.append(1 if url.startswith("https") else 0)

        # 5. IP Address Obfuscation: Navigating directly to an IP is highly suspicious
        features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0)

        # 6. Credential Harvesting Symbol: The '@' symbol ignores everything before it in a URL
        features.append(1 if "@" in url else 0)

        # 7. Domain Length
        features.append(len(domain))

        # 8. Social Engineering Keywords: Common triggers used to create urgency
        keywords = ["login", "verify", "update", "secure", "bank", "account", "support"]
        features.append(sum(1 for word in keywords if word in url.lower()))

        return features

    except Exception as e:
        print(f"[-] Feature extraction failed for {url}: {e}")
        # Return a safe zero-array if extraction completely fails
        return [0] * 8