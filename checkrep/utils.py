import requests
import constants
import ipaddress
import base64
import click


def refang_ioc(ioc: str) -> str:
    return ioc.replace('[', '').replace(']', '')


def get_virustotal_report(endpoint_url: str) -> dict | None:
    """Send GET request to Virus Total API and return parsed JSON response

    Returns None if resource not found (HTTP 404)
    """

    headers = {
        "accept": "application/json",
        "x-apikey": constants.API_KEY
    }
    response = requests.get(endpoint_url, headers=headers, timeout=5)

    if response.status_code == 404:
        return None

    response.raise_for_status()  # HTTP error if status is 4xx or 5xx
    return response.json()


def print_ioc_summary(ioc_type: str, ioc_value: str, vt_data: dict) -> None:
    """Extracts and prints relevant info from VirusTotal report"""
    stats = vt_data['data']['attributes']['last_analysis_stats']
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless = stats.get("harmless", 0) + stats.get("undetected", 0)

    # Apply colors to output dynamically
    if malicious > 0:
        malicious_str = click.style(str(malicious), fg="red", bold=True)
        suspicious_str = (
            click.style(str(suspicious), fg="yellow", bold=True)
            if suspicious > 0
            else str(suspicious)
        )
        clean_str = (
            click.style(str(harmless), fg="green", bold=True)
            if harmless > 0
            else str(harmless)
        )
        status = click.style("[MALICIOUS]", fg="red", bold=True)
        click.echo(
            f"{status} {ioc_type} {ioc_value} - Malicious: {malicious_str} | Suspicious: {suspicious_str} | Clean: {clean_str}"
        )

    elif suspicious > 0:
        suspicious_str = click.style(
            str(suspicious), fg="yellow", bold=True)
        status = click.style("[SUSPICIOUS]", fg="yellow", bold=True)
        click.echo(
            f"{status} {ioc_type} {ioc_value} - Malicious: 0 | Suspicious: {suspicious_str} | Clean: {harmless}"
        )

    else:
        status = click.style("[CLEAN]", fg="green", bold=True)
        clean_str_single_report = click.style(
            f"0 malicious / 0 suspicious", fg="green")
        click.echo(
            f"{status} {ioc_type} {ioc_value} is clean ({clean_str_single_report}, {harmless} clean/undetected vendors)"
        )


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

    try:
        data = get_virustotal_report(endpoint)
        if data is None:
            print(
                f"{ioc_type} '{display_ioc}' not found in VirusTotal.")
            return

        print_ioc_summary(ioc_type, display_ioc, data)

    except requests.exceptions.HTTPError as err:
        print(
            f"Error fetching VirusTotal report for {display_ioc}: Invalid IoC. Status {err.response.status_code} - {err.response.reason}")
    except requests.exceptions.RequestException:
        print("Network error while reaching VirusTotal API")
