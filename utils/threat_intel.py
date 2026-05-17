import csv
import json
import os
import re
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv


INPUT_FILE = "outputs/processed_alert_test_iocs.json"
JSON_OUTPUT_FILE = "outputs/enriched_alert.json"
CSV_OUTPUT_FILE = "outputs/enriched_alert.csv"

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")


def load_processed_alert() -> Dict[str, Any]:
    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def save_json(data: Dict[str, Any]) -> None:
    os.makedirs("outputs", exist_ok=True)

    with open(JSON_OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def flatten_value(value: Any) -> str:
    if isinstance(value, dict) or isinstance(value, list):
        return json.dumps(value, ensure_ascii=False)

    if value is None:
        return ""

    return str(value)


def save_csv(data: Dict[str, Any]) -> None:
    os.makedirs("outputs", exist_ok=True)

    flattened_data = {}

    for key, value in data.items():
        flattened_data[key] = flatten_value(value)

    with open(CSV_OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=flattened_data.keys())
        writer.writeheader()
        writer.writerow(flattened_data)


def is_available(value: Optional[str]) -> bool:
    if value is None:
        return False

    value = str(value).strip()

    if value == "":
        return False

    if value.lower() in ["not available", "unknown", "none", "null", "n/a"]:
        return False

    return True


def is_ip_address(value: str) -> bool:
    pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if not re.match(pattern, value):
        return False

    parts = value.split(".")

    for part in parts:
        if int(part) < 0 or int(part) > 255:
            return False

    return True


def is_private_ip(ip_address: str) -> bool:
    if not is_ip_address(ip_address):
        return False

    parts = ip_address.split(".")
    first = int(parts[0])
    second = int(parts[1])

    if first == 10:
        return True

    if first == 172 and 16 <= second <= 31:
        return True

    if first == 192 and second == 168:
        return True

    if first == 127:
        return True

    return False


def is_external_domain(domain: str) -> bool:
    if not is_available(domain):
        return False

    # Example: BETHANYCHUCHU is likely an internal AD/domain name, not an external domain.
    if "." not in domain:
        return False

    return True


def extract_iocs(alert: Dict[str, Any]) -> Dict[str, Any]:
    source_ip = alert.get("source_ip")
    destination_ip = alert.get("destination_ip")
    event_domain = alert.get("event_domain")
    possible_file_name = alert.get("possible_file_name")

    file_hash = (
        alert.get("file_hash")
        or alert.get("sha256")
        or alert.get("sha1")
        or alert.get("md5")
        or alert.get("entity_file_hash")
    )

    ip_indicators = []

    if is_available(source_ip) and is_ip_address(source_ip) and not is_private_ip(source_ip):
        ip_indicators.append(source_ip)

    if is_available(destination_ip) and is_ip_address(destination_ip) and not is_private_ip(destination_ip):
        ip_indicators.append(destination_ip)

    domain_indicators = []

    if is_available(event_domain) and is_external_domain(event_domain):
        domain_indicators.append(event_domain)

    return {
        "possible_file_name": possible_file_name,
        "file_hash": file_hash,
        "ip_indicators": list(set(ip_indicators)),
        "domain_indicators": list(set(domain_indicators))
    }


def query_virustotal_file_hash(file_hash: str) -> Dict[str, Any]:
    if not VT_API_KEY:
        return {
            "status": "skipped",
            "reason": "VT_API_KEY is missing."
        }

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=20)

        if response.status_code == 404:
            return {
                "status": "not_found",
                "indicator": file_hash,
                "reason": "File hash was not found in VirusTotal."
            }

        if response.status_code != 200:
            return {
                "status": "error",
                "indicator": file_hash,
                "status_code": response.status_code,
                "response": response.text[:500]
            }

        result = response.json()
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "status": "completed",
            "indicator": file_hash,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
            "meaningful_name": attributes.get("meaningful_name"),
            "first_submission_date": attributes.get("first_submission_date"),
            "last_analysis_date": attributes.get("last_analysis_date")
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "indicator": file_hash,
            "reason": str(error)
        }


def query_virustotal_ip(ip_address: str) -> Dict[str, Any]:
    if not VT_API_KEY:
        return {
            "status": "skipped",
            "reason": "VT_API_KEY is missing."
        }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=20)

        if response.status_code != 200:
            return {
                "status": "error",
                "indicator": ip_address,
                "status_code": response.status_code,
                "response": response.text[:500]
            }

        result = response.json()
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "status": "completed",
            "indicator": ip_address,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner")
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "indicator": ip_address,
            "reason": str(error)
        }


def query_virustotal_domain(domain: str) -> Dict[str, Any]:
    if not VT_API_KEY:
        return {
            "status": "skipped",
            "reason": "VT_API_KEY is missing."
        }

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=20)

        if response.status_code != 200:
            return {
                "status": "error",
                "indicator": domain,
                "status_code": response.status_code,
                "response": response.text[:500]
            }

        result = response.json()
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "status": "completed",
            "indicator": domain,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
            "registrar": attributes.get("registrar"),
            "creation_date": attributes.get("creation_date")
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "indicator": domain,
            "reason": str(error)
        }


def query_abuseipdb(ip_address: str) -> Dict[str, Any]:
    if not ABUSEIPDB_API_KEY:
        return {
            "status": "skipped",
            "reason": "ABUSEIPDB_API_KEY is missing."
        }

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": ""
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=20)

        if response.status_code != 200:
            return {
                "status": "error",
                "indicator": ip_address,
                "status_code": response.status_code,
                "response": response.text[:500]
            }

        result = response.json().get("data", {})

        return {
            "status": "completed",
            "indicator": ip_address,
            "abuse_confidence_score": result.get("abuseConfidenceScore"),
            "total_reports": result.get("totalReports"),
            "country_code": result.get("countryCode"),
            "isp": result.get("isp"),
            "domain": result.get("domain"),
            "usage_type": result.get("usageType"),
            "last_reported_at": result.get("lastReportedAt")
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "indicator": ip_address,
            "reason": str(error)
        }


def query_otx_indicator(indicator_type: str, indicator_value: str) -> Dict[str, Any]:
    if not OTX_API_KEY:
        return {
            "status": "skipped",
            "reason": "OTX_API_KEY is missing."
        }

    url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator_value}/general"

    headers = {
        "X-OTX-API-KEY": OTX_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=20)

        if response.status_code != 200:
            return {
                "status": "error",
                "indicator": indicator_value,
                "indicator_type": indicator_type,
                "status_code": response.status_code,
                "response": response.text[:500]
            }

        result = response.json()
        pulse_info = result.get("pulse_info", {})

        related_pulses = []

        for pulse in pulse_info.get("pulses", [])[:5]:
            related_pulses.append(pulse.get("name"))

        return {
            "status": "completed",
            "indicator": indicator_value,
            "indicator_type": indicator_type,
            "pulse_count": pulse_info.get("count", 0),
            "related_pulses": related_pulses,
            "sections_available": result.get("sections", [])
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "indicator": indicator_value,
            "indicator_type": indicator_type,
            "reason": str(error)
        }


def calculate_enrichment_risk(threat_intel: Dict[str, Any]) -> Dict[str, Any]:
    risk_score = 0
    reasons = []

    vt_file_result = threat_intel.get("virustotal", {}).get("file_hash")

    if vt_file_result and vt_file_result.get("status") == "completed":
        malicious = vt_file_result.get("malicious", 0)
        suspicious = vt_file_result.get("suspicious", 0)

        if malicious > 0:
            risk_score += 40
            reasons.append(
                f"VirusTotal reported {malicious} malicious detection(s) for the file hash."
            )

        if suspicious > 0:
            risk_score += 15
            reasons.append(
                f"VirusTotal reported {suspicious} suspicious detection(s) for the file hash."
            )

    for result in threat_intel.get("virustotal", {}).get("ip_results", []):
        if result.get("status") == "completed":
            malicious = result.get("malicious", 0)
            suspicious = result.get("suspicious", 0)

            if malicious > 0:
                risk_score += 25
                reasons.append(
                    f"VirusTotal reported {malicious} malicious detection(s) for IP {result.get('indicator')}."
                )

            if suspicious > 0:
                risk_score += 10
                reasons.append(
                    f"VirusTotal reported {suspicious} suspicious detection(s) for IP {result.get('indicator')}."
                )

    for result in threat_intel.get("virustotal", {}).get("domain_results", []):
        if result.get("status") == "completed":
            malicious = result.get("malicious", 0)
            suspicious = result.get("suspicious", 0)

            if malicious > 0:
                risk_score += 25
                reasons.append(
                    f"VirusTotal reported {malicious} malicious detection(s) for domain {result.get('indicator')}."
                )

            if suspicious > 0:
                risk_score += 10
                reasons.append(
                    f"VirusTotal reported {suspicious} suspicious detection(s) for domain {result.get('indicator')}."
                )

    for result in threat_intel.get("abuseipdb", {}).get("ip_results", []):
        if result.get("status") == "completed":
            abuse_score = result.get("abuse_confidence_score") or 0

            if abuse_score >= 80:
                risk_score += 30
                reasons.append(
                    f"AbuseIPDB abuse confidence score is high for {result.get('indicator')}: {abuse_score}."
                )

            elif abuse_score >= 30:
                risk_score += 15
                reasons.append(
                    f"AbuseIPDB abuse confidence score is moderate for {result.get('indicator')}: {abuse_score}."
                )

    for result in threat_intel.get("alienvault_otx", {}).get("otx_results", []):
        if result.get("status") == "completed":
            pulse_count = result.get("pulse_count") or 0

            if pulse_count > 0:
                risk_score += 20
                reasons.append(
                    f"AlienVault OTX found {pulse_count} related pulse(s) for {result.get('indicator')}."
                )

    if risk_score == 0:
        reasons.append(
            "No confirmed malicious external intelligence was found, or no usable IOC was available."
        )

    if risk_score >= 70:
        risk_level = "High"
    elif risk_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "enrichment_risk_score": risk_score,
        "enrichment_risk_level": risk_level,
        "enrichment_risk_reasons": reasons
    }


def enrich_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    iocs = extract_iocs(alert)

    file_name = iocs.get("possible_file_name")
    file_hash = iocs.get("file_hash")
    ip_indicators = iocs.get("ip_indicators", [])
    domain_indicators = iocs.get("domain_indicators", [])

    notes = []

    if is_available(file_name) and not is_available(file_hash):
        notes.append(
            f"{file_name} was extracted, but no file hash was found. VirusTotal and OTX file reputation checks require a hash."
        )

    if len(ip_indicators) == 0:
        notes.append(
            "No usable public IP indicators were found. AbuseIPDB, VirusTotal IP, and OTX IP lookups were skipped."
        )

    if len(domain_indicators) == 0:
        notes.append(
            "No usable external domain indicators were found. VirusTotal domain and OTX domain lookups were skipped."
        )

    threat_intel = {
        "iocs": iocs,
        "virustotal": {
            "file_hash": None,
            "ip_results": [],
            "domain_results": []
        },
        "abuseipdb": {
            "ip_results": []
        },
        "alienvault_otx": {
            "otx_results": []
        },
        "notes": notes
    }

    if is_available(file_hash):
        threat_intel["virustotal"]["file_hash"] = query_virustotal_file_hash(file_hash)

        threat_intel["alienvault_otx"]["otx_results"].append(
            query_otx_indicator("file", file_hash)
        )
    else:
        threat_intel["virustotal"]["file_hash"] = {
            "status": "skipped",
            "reason": "No file hash was available."
        }

    for ip_address in ip_indicators:
        threat_intel["virustotal"]["ip_results"].append(
            query_virustotal_ip(ip_address)
        )

        threat_intel["abuseipdb"]["ip_results"].append(
            query_abuseipdb(ip_address)
        )

        threat_intel["alienvault_otx"]["otx_results"].append(
            query_otx_indicator("IPv4", ip_address)
        )

    for domain in domain_indicators:
        threat_intel["virustotal"]["domain_results"].append(
            query_virustotal_domain(domain)
        )

        threat_intel["alienvault_otx"]["otx_results"].append(
            query_otx_indicator("domain", domain)
        )

    enrichment_risk = calculate_enrichment_risk(threat_intel)

    enriched_alert = {
        **alert,
        "current_stage": "enrichment_completed",
        "threat_intelligence": threat_intel,
        "enrichment_risk_score": enrichment_risk["enrichment_risk_score"],
        "enrichment_risk_level": enrichment_risk["enrichment_risk_level"],
        "enrichment_risk_reasons": enrichment_risk["enrichment_risk_reasons"]
    }

    return enriched_alert


def main() -> None:
    processed_alert = load_processed_alert()
    enriched_alert = enrich_alert(processed_alert)

    save_json(enriched_alert)
    save_csv(enriched_alert)

    print(json.dumps(enriched_alert, indent=4))
    print()
    print(f"Threat intelligence JSON saved to: {JSON_OUTPUT_FILE}")
    print(f"Threat intelligence CSV saved to: {CSV_OUTPUT_FILE}")


if __name__ == "__main__":
    main()