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
@click.option('--country', prompt='Enter country',
              help='The country of the IP to analyze.')
@click.option('--ip', prompt='Enter defanged IP address',
              help='The IP address to analyze, such as 51[.]254[.]69[.]91')
def is_ip_malicious(country, ip):
    """Basic reputation checker that takes in an IP adress and checks whether it is malicious."""
    spammer = SPAMMER_IP_ADDRESS
    malicious = MALICIOUS_IP_ADDRESS
    url = f"{IP_ADDRESS_BASE_URL}{ip}"

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)
    url_data = response.json()
    print(json.dumps(url_data, indent=2))

    if ip == spammer:
        click.echo(f"IP address {ip} from {country} is a spammer!")
    elif ip == malicious:
        click.echo(f"IP address {ip} from {country} is malicious!")
    else:
        click.echo(f"IP address {ip} from {country} is benign.")


if __name__ == '__main__':
    is_ip_malicious()

  # TODO: regex logic to accept defanged input and refang it upon sending the API request
    # TODO: logic to find the key-value pair matching the IP category (spammer, phishing, etc.)
    # TODO: logic for receiving other IoCs as input
    # TODO: logic for uploading logs and scanning through IoCs, then returning a threat summary
