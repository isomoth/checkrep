import requests
import json
import click
import os
import ipaddress
import re
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv('API_KEY')
SPAMMER_IP_ADDRESS = os.getenv('SPAMMER_IP_ADDRESS')
LOG_FILE_PATH = os.getenv('LOG_FILE_PATH')
IP_ADDRESS_BASE_URL = os.getenv('IP_ADDRESS_BASE_URL')
FILE_PATH_PATTERN = re.compile(r'(?i)^.*\.(txt|json|xml)$')
IP_PATTERN = re.compile(
    r'((?:\d{1,3}\.){3}\d{1,3})'
)


@click.command()
@click.option('--ioc', prompt='Enter a defanged IP address or log file path')
def is_ip_malicious(ioc):
    """Basic reputation checker that takes in an IP adress and checks whether it is malicious."""
    refanged_ip = ioc.translate({ord(i): None for i in "[]"})

    is_ip = IP_PATTERN.match(refanged_ip)
    is_log_file = FILE_PATH_PATTERN.match(ioc)

    if is_ip:
        ip_request = f"{IP_ADDRESS_BASE_URL}{refanged_ip}"

        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }

        response = requests.get(ip_request, headers=headers)
        url_data = response.json()
        print(json.dumps(url_data, indent=2))

    elif is_log_file:
        valid_ip_list = []
        with open(
                ioc, 'r', encoding="utf-8") as file:
            for line in file:
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
    is_ip_malicious()  # noqa: E1120


# General
# TODO: interview SOC analysts to find out which IoCs are relevant and which data they want to see in the report

# Output
# TODO: make the API request reusable
# TODO: Read up on how to interpret IP VirusTotal report
    # Example logic:
    # Check attributes.malicious, if count = 0, ip is benign
    # If count = 1, ip should be investigated
    # If count > 5, ip is malicious
# TODO: exclude benign IPs from output
# TODO: logic to find the key-value pair matching the IP category (spammer, phishing, etc.)
# TODO: logic for receiving other IoCs as input
# TODO: logic for uploading logs and scanning through IoCs, then returning a threat summary
