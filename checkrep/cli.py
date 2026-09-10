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
IP_ADDRESS_BASE_URL = os.getenv('IP_ADDRESS_BASE_URL')
LOG_FILE_PATH = os.getenv('LOG_FILE_PATH')
IP_PATTERN = re.compile(
    r'((?:\d{1,3}\.){3}\d{1,3})'
)


@click.command()
@click.option('--ioc', prompt='Enter a defanged IP address or log file path')
def is_ip_malicious(ioc):
    """Basic reputation checker that takes in an IP adress and checks whether it is malicious."""
    ip = SPAMMER_IP_ADDRESS
    log_file = LOG_FILE_PATH
    refanged_ip = ip.translate({ord(i): None for i in "[]"})

    if ioc == ip:

        ip_request = f"{IP_ADDRESS_BASE_URL}{refanged_ip}"

        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }

        response = requests.get(ip_request, headers=headers)
        url_data = response.json()
        print(json.dumps(url_data, indent=2))

    elif ioc == log_file:
        valid_ip_list = []
        with open(
                log_file, 'r', encoding="utf-8") as file:
            for line in file:
                ip_addresses = IP_PATTERN.findall(line)
                for ip_address in ip_addresses:
                    ip_object = ipaddress.ip_address(ip_address)
                    valid_ip_list.append(ip_object)

            print("The log contains the following IP addresses: ", valid_ip_list)

    else:
        print("Invalid input, try again.")


if __name__ == '__main__':
    is_ip_malicious()  # noqa: E1120


# General
# TODO: interview SOC analysts to find out which IoCs are relevant and which data they want to see in the report

# Input
# TODO: read from user input instead of hard-coded values
# TODO: receive and read through a text file regardless of its format
# TODO: exclude private IPs
# Output
 # TODO: Read up on how to interpret IP VirusTotal report
    # Example logic:
    # Check attributes.malicious, if count = 0, ip is benign
    # If count = 1, ip should be investigated
    # If count > 5, ip is malicious
# TODO: exclude benign IPs from output
# TODO: return malicious and suspicious IPs
# TODO: logic to find the key-value pair matching the IP category (spammer, phishing, etc.)
# TODO: logic for receiving other IoCs as input
# TODO: logic for uploading logs and scanning through IoCs, then returning a threat summary
