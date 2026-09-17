import requests
import constants


def get_virustotal_report(endpoint_url: str) -> dict:
    """Send GET request to Virus Total API and return parsed JSON response"""

    headers = {
        "accept": "application/json",
        "x-apikey": constants.API_KEY
    }
    response = requests.get(endpoint_url, headers=headers)
    response.raise_for_status()  # HTTP error if status is 4xx or 5xx
    return response.json()


def print_ioc_summary(ioc_type: str, ioc_value: str, vt_data: dict) -> None:
    """Extracts and prints relevant info from VirusTotal report"""
    stats = vt_data['data']['attributes']['last_analysis_stats']
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    print(f"{ioc_type} {ioc_value} was reported as malicious by {malicious} vendors and suspicious by {suspicious} vendors")
