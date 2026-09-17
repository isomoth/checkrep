import json
import requests
import click
import os
import ipaddress
import re
from dotenv import load_dotenv
import base64
import constants
import utils

load_dotenv()


@click.command()
@click.option('--ioc', prompt='Enter a defanged IP address or log file path')
def check_reputation(ioc: str):
    """Basic reputation checker for URL, IP, hashes, domains and log files."""

    refanged_ioc = ioc.translate({ord(i): None for i in "[]"})
    is_ip = constants.IP_PATTERN.match(refanged_ioc)
    is_url = constants.URL_PATTERN.match(refanged_ioc)
    is_hash = constants.HASH_PATTERN.match(ioc)
    is_domain = constants.DOMAIN_PATTERN.match(refanged_ioc)
    is_log_file = constants.FILE_PATH_PATTERN.match(ioc)

    if is_ip:
        ip_endpoint = f"{constants.BASE_URL}{constants.IP_ADDRESS_ENDPOINT}{refanged_ioc}"
        ip_data = utils.get_virustotal_report(ip_endpoint)
        utils.print_ioc_summary("Public IP", refanged_ioc, ip_data)

    elif is_url:
        # VirusTotal API only accepts URL identifiers as SHA-256 (canonized URL) or the string as converted to base64
        # I've selected base64 as the chosen identifier
        url_id = base64.urlsafe_b64encode(
            ioc.encode()).decode().strip("=")
        url_endpoint = f"{constants.BASE_URL}{constants.URL_ADDRESS_ENDPOINT}{url_id}"
        url_data = utils.get_virustotal_report(url_endpoint)
        utils.print_ioc_summary("URL", ioc, url_data)

    elif is_hash:
        hash_endpoint = f"{constants.BASE_URL}{constants.HASH_ENDPOINT}{ioc}"
        hash_data = utils.get_virustotal_report(hash_endpoint)
        utils.print_ioc_summary("File hash", ioc, hash_data)

    elif is_domain:
        domain_endpoint = f"{constants.BASE_URL}{constants.DOMAIN_ENDPOINT}{ioc}"
        domain_data = utils.get_virustotal_report(domain_endpoint)
        utils.print_ioc_summary("Domain", ioc, domain_data)

    elif is_log_file:
        valid_ip_list = set()

        with open(
                ioc, 'r', encoding="utf-8") as file:
            for line in file:
                ip_addresses = constants.IP_PATTERN.findall(line)
                for ip_address in ip_addresses:
                    ip_object = ipaddress.ip_address(ip_address)
                    if not (ip_object.is_private or ip_object.is_loopback or ip_object.is_reserved):
                        valid_ip_list.add(str(ip_object))

        for public_ip in valid_ip_list:
            public_ip_endpoint = f"{constants.BASE_URL}{constants.IP_ADDRESS_ENDPOINT}{public_ip}"
            ips_data = utils.get_virustotal_report(
                public_ip_endpoint)
            utils.print_ioc_summary(
                "Public IP", public_ip, ips_data)

    else:
        print("Invalid input, try again.")


if __name__ == '__main__':
    check_reputation()  # noqa: E1120

# TODO: add logic for parsing any kind of ioc
