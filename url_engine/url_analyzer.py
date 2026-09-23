from urllib.parse import urlparse
import ipaddress
from difflib import SequenceMatcher


SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".zip"
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "password",
    "credential",
    "update",
    "signin",
    "bank",
    "payment" }
    
KNOWN_BRANDS = {
    "paypal",
    "google",
    "microsoft",
    "amazon",
    "apple",
    "facebook",
    "instagram",
    "sbi"
}
    
def detect_typosquatting(domain):
    domain_name = domain.split(".")[0]

    for brand in KNOWN_BRANDS:
        similarity = SequenceMatcher(
            None,
            domain_name,
            brand
        ).ratio()

        if 0.75 <= similarity < 1.0:
            return brand

    return None


def analyze_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Check if the domain is an IP address
    is_ip = False

    try:
        ipaddress.ip_address(domain)
        is_ip = True
    except ValueError:
        pass

    # Find suspicious keywords
    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            found_keywords.append(keyword)

    # Check suspicious TLD
    suspicious_tld = any(
        domain.endswith(tld)
        for tld in SUSPICIOUS_TLDS
        
    )
    possible_brand = detect_typosquatting(domain)

    # RISK SCORING
    # -------------------------
    # -------------------------
    # RISK SCORING
    # -------------------------

    score = 0
    indicators = []
    evidence = []

    if suspicious_tld:
        score += 20
        indicators.append("Suspicious TLD")
        evidence.append(
            f"Domain uses a potentially risky TLD: {domain}"
        )

    if is_ip:
        score += 25
        indicators.append("IP address used instead of domain")
        evidence.append(
            f"The URL uses an IP address: {domain}"
        )

    if found_keywords:
        score += 10
        indicators.append("Suspicious URL keywords")
        evidence.append(
            "URL contains security-sensitive keywords: "
            + ", ".join(found_keywords)
        )

    if possible_brand:
        score += 25
        indicators.append("Possible typosquatting")
        evidence.append(
            f"Domain resembles or contains the known brand: {possible_brand}"
        )

    if len(url) > 100:
        score += 10
        indicators.append("Unusually long URL")
        evidence.append(
            f"URL length is {len(url)} characters"
        )

    score = min(score, 100)

    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "url_score": score,
        "risk_level": risk_level,
        "domain": domain,
        "indicators": indicators,
        "evidence": evidence
    }


# Test URL
url = "https://paypa1-secure-login.xyz/verify-account"

result = analyze_url(url)

print(result)