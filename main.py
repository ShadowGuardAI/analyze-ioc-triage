import argparse
import logging
import pandas as pd
import os
import hashlib
import requests  # For interacting with APIs

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Quickly triage multiple IOCs against public threat intelligence feeds.")
    parser.add_argument("ioc_file", help="Path to a file containing IOCs (one IOC per line).")
    parser.add_argument("--output", "-o", default="ioc_report.csv", help="Path to the output CSV file. Defaults to ioc_report.csv")
    parser.add_argument("--virustotal_api_key", "-vt", help="Your VirusTotal API key (optional).")
    parser.add_argument("--abuseipdb_api_key", "-ab", help="Your AbuseIPDB API key (optional).")  # Added AbuseIPDB API Key
    return parser

def validate_ioc(ioc):
    """
    Validates the given IOC based on type (IP, domain, hash).  Basic validation only.
    More robust validation can be implemented later using regex etc.
    Args:
        ioc (str): The IOC to validate.
    Returns:
        str: The IOC type ('ip', 'domain', 'hash', or 'unknown').
    """
    try:
        # Basic IP validation (e.g., four octets separated by dots)
        if ioc.count('.') == 3 and all(part.isdigit() and 0 <= int(part) <= 255 for part in ioc.split('.')):
            return 'ip'

        # Basic domain validation (e.g., contains a dot)
        if '.' in ioc:
            return 'domain'

        # Basic hash validation (e.g., common hash lengths)
        if len(ioc) in [32, 40, 64, 128]:
            return 'hash'

        return 'unknown'  # Indicate that the IOC type couldn't be determined
    except Exception as e:
        logging.error(f"Error validating IOC: {ioc}. Error: {e}")
        return 'unknown'

def get_virustotal_report(ioc, api_key):
    """
    Retrieves a report from VirusTotal for the given IOC.
    Args:
        ioc (str): The IOC to look up.
        api_key (str): Your VirusTotal API key.
    Returns:
        dict: A dictionary containing the VirusTotal report, or None if an error occurred.
    """
    if not api_key:
        logging.warning("VirusTotal API key not provided. Skipping VirusTotal analysis.")
        return None

    ioc_type = validate_ioc(ioc)
    if ioc_type == 'ip':
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == 'domain':
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type == 'hash':
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    else:
        logging.warning(f"Unsupported IOC type for VirusTotal: {ioc}")
        return None

    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error communicating with VirusTotal for {ioc}: {e}")
        return None

def get_abuseipdb_report(ip_address, api_key):
    """
    Retrieves a report from AbuseIPDB for the given IP address.
    Args:
        ip_address (str): The IP address to look up.
        api_key (str): Your AbuseIPDB API key.
    Returns:
        dict: A dictionary containing the AbuseIPDB report, or None if an error occurred.
    """
    if not api_key:
        logging.warning("AbuseIPDB API key not provided. Skipping AbuseIPDB analysis.")
        return None

    if validate_ioc(ip_address) != 'ip':
        logging.warning(f"Invalid IP address for AbuseIPDB: {ip_address}")
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90  # You can adjust this as needed
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Raise HTTPError for bad responses
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error communicating with AbuseIPDB for {ip_address}: {e}")
        return None


def main():
    """
    Main function to orchestrate the IOC triage process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        with open(args.ioc_file, 'r') as f:
            iocs = [line.strip() for line in f]
    except FileNotFoundError:
        logging.error(f"IOC file not found: {args.ioc_file}")
        return
    except Exception as e:
        logging.error(f"Error reading IOC file: {e}")
        return

    results = []
    for ioc in iocs:
        ioc_type = validate_ioc(ioc)
        logging.info(f"Analyzing IOC: {ioc} (Type: {ioc_type})")

        vt_report = None
        if args.virustotal_api_key:
             vt_report = get_virustotal_report(ioc, args.virustotal_api_key)

        ab_report = None
        if ioc_type == 'ip' and args.abuseipdb_api_key:
            ab_report = get_abuseipdb_report(ioc, args.abuseipdb_api_key) # Only check IPs on AbuseIPDB

        # Extract relevant data from reports (customize as needed)
        vt_malicious = None
        vt_suspicious = None
        vt_harmless = None
        vt_undetected = None
        vt_timeout = None

        if vt_report and vt_report.get("data") and vt_report["data"].get("attributes") and vt_report["data"]["attributes"].get("last_analysis_stats"):

            vt_stats = vt_report["data"]["attributes"]["last_analysis_stats"]
            vt_malicious = vt_stats.get("malicious")
            vt_suspicious = vt_stats.get("suspicious")
            vt_harmless = vt_stats.get("harmless")
            vt_undetected = vt_stats.get("undetected")
            vt_timeout = vt_stats.get("timeout")

        ab_abuse_confidence_score = None
        ab_total_reports = None
        ab_country_code = None
        if ab_report and ab_report.get("data"):
            ab_abuse_confidence_score = ab_report["data"].get("abuseConfidenceScore")
            ab_total_reports = ab_report["data"].get("totalReports")
            ab_country_code = ab_report["data"].get("countryCode")

        results.append({
            "IOC": ioc,
            "IOC Type": ioc_type,
            "VT Malicious": vt_malicious,
            "VT Suspicious": vt_suspicious,
            "VT Harmless": vt_harmless,
            "VT Undetected": vt_undetected,
            "VT Timeout": vt_timeout,
            "AbuseIPDB Confidence": ab_abuse_confidence_score,
            "AbuseIPDB Total Reports": ab_total_reports,
            "AbuseIPDB Country Code": ab_country_code
        })

    df = pd.DataFrame(results)
    try:
        df.to_csv(args.output, index=False)
        logging.info(f"Report saved to: {args.output}")
    except Exception as e:
        logging.error(f"Error saving report to CSV: {e}")

if __name__ == "__main__":
    main()