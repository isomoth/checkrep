import requests
import json
import click
import os
import ipaddress
import re
from dotenv import load_dotenv
import base64

load_dotenv()
API_KEY = os.getenv('API_KEY')
LOG_FILE_PATH = os.getenv('LOG_FILE_PATH')
IP_ADDRESS_BASE_URL = os.getenv('IP_ADDRESS_BASE_URL')
FILE_PATH_PATTERN = re.compile(r'(?i)^.*\.(txt|json|xml)$')
URL_ADDRESS_BASE_URL = os.getenv('URL_ADDRESS_BASE_URL')
IP_PATTERN = re.compile(
    r'((?:\d{1,3}\.){3}\d{1,3})'
)
URL_PATTERN = re.compile(
    r'https?://([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:[0-9]+)?(/[^\s]*)?(\?[^\s]*)?$'
)


@click.command()
@click.option('--ioc', prompt='Enter a defanged IP address or log file path')
def check_reputation(ioc):
    """Basic reputation checker that takes in an IP adress and checks whether it is malicious."""

    refanged_ioc = ioc.translate({ord(i): None for i in "[]"})
    is_ip = IP_PATTERN.match(refanged_ioc)
    is_log_file = FILE_PATH_PATTERN.match(ioc)
    is_url = URL_PATTERN.match(refanged_ioc)

    if is_ip:
        ip_request = f"{IP_ADDRESS_BASE_URL}{refanged_ioc}"
        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }

        response = requests.get(ip_request, headers=headers)
        url_data = response.json()
        print(json.dumps(url_data, indent=2))
    elif is_url:
        # VirusTotal API only accepts URL identifiers as SHA-256 (canonized URL) or the string as converted to base64
        # I've selected base64 as the chosen identifier
        url_id = base64.urlsafe_b64encode(
            ioc.encode()).decode().strip("=")
        url_request = f"{URL_ADDRESS_BASE_URL}{url_id}"

        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }

        url_response = requests.get(url_request, headers=headers)
        url_report_data = url_response.json()
        print(json.dumps(url_report_data, indent=2))

    elif is_log_file:
        valid_ip_list = []
        with open(
                ioc, 'r', encoding="utf-8") as file:
            for line in file:
                # TODO: Logic to parse other IoCs apart from IP addresses
                ip_addresses = IP_PATTERN.findall(line)
                for ip_address in ip_addresses:
                    ip_object = ipaddress.ip_address(ip_address)
                    if not ip_object.is_private or ip_object.is_loopback or ip_object.is_reserved:
                        valid_ip_list.append(ip_object)

                        for public_ip in valid_ip_list:
                            public_ip_request = f"{IP_ADDRESS_BASE_URL}{public_ip}"
                            headers = {
                                "accept": "application/json",
                                "x-apikey": API_KEY
                            }

                            response = requests.get(
                                public_ip_request, headers=headers)
                            url_data = response.json()

                        print("Public IP", public_ip, "was reported as malicious by", url_data['data']['attributes']
                              ['last_analysis_stats']['malicious'], "vendors and suspicious by", url_data['data']['attributes']
                              ['last_analysis_stats']['suspicious'], "vendors")

    else:
        print("Invalid input, try again.")


if __name__ == '__main__':
    check_reputation()  # noqa: E1120


# General
# TODO: interview SOC analysts to find out which IoCs are relevant and which data they want to see in the report

# Output
# TODO: make the API request reusable
# TODO: move relevant constants to a file, make API base URL reusable
# TODO: logic for URL handling (including relevant threat summary information)
# TODO: logic for hashes (incl. respective threat summary)
# TODO: logic for domains (same as for hashes and URLs)
# TODO: logic for uploading logs and scanning through IoCs, then returning a threat summary
