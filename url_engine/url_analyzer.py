import re
import ipaddress
from urllib.parse import urlparse
from difflib import SequenceMatcher
import tldextract

# ---------------------------------------------------------
# CONSTANTS & CONFIGURATION
# ---------------------------------------------------------

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "zip", "work", "country", 
    "gq", "cf", "tk", "ml", "ga", "fit", "buzz"
}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "secure", "account",
    "password", "credential", "update", "signin", "bank", 
    "payment", "confirm", "billing", "support", "auth"
}

KNOWN_BRANDS = {
    "paypal", "google", "microsoft", "amazon", "apple", 
    "facebook", "instagram", "sbi", "netflix", "chase", 
    "wellsfargo", "binance", "coinbase"
}


# ---------------------------------------------------------
# HELPER DETECTION FUNCTIONS
# ---------------------------------------------------------

def detect_typosquatting_and_impersonation(extracted_domain):
    """
    Splits SLD by hyphens and checks individual tokens against known brands 
    using exact matches and Levenshtein similarity.
    """
    sld = extracted_domain.domain  # Second-Level Domain (e.g. 'paypa1-secure-login')
    tokens = sld.replace("-", " ").split()
    
    for token in tokens:
        for brand in KNOWN_BRANDS:
            # 1. Direct match embedded in hyphenated domain (e.g., paypal-secure.com)
            if brand == token:
                return brand, "direct impersonation"
            
            # 2. Fuzzy match for typosquatting (e.g., paypa1 vs paypal)
            similarity = SequenceMatcher(None, token, brand).ratio()
            if 0.75 <= similarity < 1.0:
                return brand, "typosquatting"

    return None, None


def detect_obfuscation(url, hostname):
    """
    Detects tricks like @ symbols, excessive percent-encoding, 
    and nested URLs inside parameters.
    """
    indicators = []
    evidence = []
    score = 0

    # 1. Userinfo / @ symbol trick (e.g., https://google.com@evil.com)
    if "@" in hostname:
        score += 30
        indicators.append("URL Credentials Obfuscation (@)")
        evidence.append("URL uses '@' symbol to obscure actual destination host")

    # 2. Excessive percent-encoding (%20, %2F, etc.)
    hex_matches = re.findall(r"%[0-9a-fA-F]{2}", url)
    if len(hex_matches) > 3:
        score += 15
        indicators.append("Excessive URL Encoding")
        evidence.append(f"Excessive hex encoding detected ({len(hex_matches)} instances)")

    # 3. Nested Protocol / URL-in-URL
    if url.lower().count("http://") + url.lower().count("https://") > 1:
        score += 20
        indicators.append("Nested Protocol/URL")
        evidence.append("Embedded HTTP/HTTPS protocol links found inside URL path or parameters")

    return score, indicators, evidence


# ---------------------------------------------------------
# MAIN ANALYZER ENGINE
# ---------------------------------------------------------

def analyze_url(url: str) -> dict:
    # Ensure scheme exists for urlparse
    formatted_url = url if url.startswith(("http://", "https://")) else f"http://{url}"
    
    extracted = tldextract.extract(formatted_url)
    parsed = urlparse(formatted_url)
    
    hostname = parsed.netloc.lower()
    registered_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain

    score = 0
    indicators = []
    evidence = []

    # 1. IP Address Detection
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
        score += 25
        indicators.append("IP address used instead of domain")
        evidence.append(f"The URL uses a raw IP address as destination: {hostname}")
    except ValueError:
        pass

    # 2. HTTPS Check
    if parsed.scheme != "https":
        score += 10
        indicators.append("Insecure Protocol (HTTP)")
        evidence.append("URL uses unencrypted HTTP instead of HTTPS")

    # 3. Suspicious TLD Detection
    if extracted.suffix in SUSPICIOUS_TLDS:
        score += 20
        indicators.append("Suspicious TLD")
        evidence.append(f"Domain uses high-risk TLD: .{extracted.suffix}")

    # 4. Brand Impersonation / Typosquatting Check
    if not is_ip:
        brand, match_type = detect_typosquatting_and_impersonation(extracted)
        if brand:
            score += 30
            indicators.append(f"Brand {match_type.capitalize()}")
            evidence.append(f"Domain token closely matches target brand '{brand}' ({match_type})")

    # 5. Keyword Detection
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    if found_keywords:
        score += 15
        indicators.append("Suspicious URL keywords")
        evidence.append("Security-sensitive keywords found: " + ", ".join(found_keywords))

    # 6. Subdomain Analysis
    if extracted.subdomain:
        sub_parts = extracted.subdomain.split(".")
        if len(sub_parts) >= 2:
            score += 15
            indicators.append("Excessive Subdomains")
            evidence.append(f"URL uses multiple subdomain levels ({extracted.subdomain})")
        
        for b in KNOWN_BRANDS:
            if b in extracted.subdomain and b != extracted.domain:
                score += 25
                indicators.append("Brand in Subdomain")
                evidence.append(f"Target brand keyword '{b}' isolated in subdomain structure")

    # 7. Obfuscation Checks
    obf_score, obf_indicators, obf_evidence = detect_obfuscation(url, hostname)
    score += obf_score
    indicators.extend(obf_indicators)
    evidence.extend(obf_evidence)

    # 8. URL Length Check
    if len(url) > 75:
        score += 10
        indicators.append("Unusually Long URL")
        evidence.append(f"URL length is excessive ({len(url)} characters)")

    # Score Normalization & Classification
    final_score = min(score, 100)

    if final_score >= 60:
        risk_level = "HIGH"
    elif final_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "url_score": final_score,
        "risk_level": risk_level,
        "domain": registered_domain,
        "indicators": indicators,
        "evidence": evidence
    }


# ---------------------------------------------------------
# EXECUTION & TESTING
# ---------------------------------------------------------

if __name__ == "__main__":
    test_url = "https://paypa1-secure-login.xyz/verify-account"
    
    result = analyze_url(test_url)
    
    print("\n--- ANALYSIS RESULT ---")
    print(f"URL:        {test_url}")
    print(f"Risk Score: {result['url_score']} / 100")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Domain:     {result['domain']}")
    print("\nIndicators:")
    for ind in result["indicators"]:
        print(f" - {ind}")
    print("\nEvidence:")
    for ev in result["evidence"]:
        print(f" - {ev}")