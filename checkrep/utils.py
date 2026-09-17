import requests
import constants
import ipaddress
import base64


def refang_ioc(ioc: str) -> str:
    return ioc.replace('[', '').replace(']', '')


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


def process_single_ioc(ioc_type: str, raw_ioc: str):
    """Process a single IoC string based on its type"""

    if ioc_type == "Public IP":
        try:
            ip_object = ipaddress.ip_address(raw_ioc)
            if ip_object.is_private or ip_object.is_loopback or ip_object.is_reserved:
                return
        except ValueError:
            return
        endpoint = f"{constants.BASE_URL}{constants.IP_ADDRESS_ENDPOINT}{raw_ioc}"
        display_ioc = raw_ioc

    elif ioc_type == "URL":
        url_id = base64.urlsafe_b64encode(
            raw_ioc.encode()).decode().strip("=")
        endpoint = f"{constants.BASE_URL}{constants.URL_ADDRESS_ENDPOINT}{url_id}"
        display_ioc = raw_ioc

    elif ioc_type == "File hash":
        endpoint = f"{constants.BASE_URL}{constants.HASH_ENDPOINT}{raw_ioc}"
        display_ioc = raw_ioc

    elif ioc_type == "Domain":
        endpoint = f"{constants.BASE_URL}{constants.DOMAIN_ENDPOINT}{raw_ioc}"
        display_ioc = raw_ioc

    data = get_virustotal_report(endpoint)
    print_ioc_summary(ioc_type, display_ioc, data)
