import requests
import json
import click
import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv('API_KEY')
SPAMMER_IP_ADDRESS = os.getenv('SPAMMER_IP_ADDRESS')
MALICIOUS_IP_ADDRESS = os.getenv('MALICIOUS_IP_ADDRESS')
IP_ADDRESS_BASE_URL = os.getenv('IP_ADDRESS_BASE_URL')


@click.command()
@click.option('--ip', prompt='Enter defanged IP address',
              help='The IP address to analyze, such as 51[.]254[.]69[.]91')
def is_ip_malicious(ip):
    """Basic reputation checker that takes in an IP adress and checks whether it is malicious."""
    refanged_ip = ip.translate({ord(i): None for i in "[]"})
    # TODO: Read up on how to interpret IP VirusTotal report
    # Example logic:
    # Check attributes.malicious, if count = 0, ip is benign
    # If count = 1, ip should be investigated
    # If count > 5, ip is malicious
    spammer = SPAMMER_IP_ADDRESS
    malicious = MALICIOUS_IP_ADDRESS
    url = f"{IP_ADDRESS_BASE_URL}{refanged_ip}"

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)
    url_data = response.json()
    print(json.dumps(url_data, indent=2))

    if ip == spammer:
        click.echo(f"IP address {ip} is a spammer!")
    elif ip == malicious:
        click.echo(f"IP address {ip} is malicious!")
    else:
        click.echo(f"IP address {ip} is benign.")


if __name__ == '__main__':
    is_ip_malicious()

# General
# TODO: interview SOC analysts to find out which IoCs are relevant and which data they want to see in the report

# Input
# TODO: receive and read through a text file regardless of its format
# TODO: find all strings matching IP addresses
# TODO: exclude private IPs
# Output
# TODO: exclude benign IPs from output
# TODO: return malicious and suspicious IPs
# TODO: logic to find the key-value pair matching the IP category (spammer, phishing, etc.)
# TODO: logic for receiving other IoCs as input
# TODO: logic for uploading logs and scanning through IoCs, then returning a threat summary
