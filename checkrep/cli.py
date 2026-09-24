import json
import requests
import click
import os
import ipaddress
import pathlib
import re
from dotenv import load_dotenv
import base64
from . import constants
from . import utils
import sys


load_dotenv()


@click.command()
@click.option(
    "--ioc",
    prompt="Enter a defanged IP address, URL, domain, file hash or log file path", help="A string in the form of an IP address, URL, domain, file hash, or log file path."
)
def check_reputation(ioc: str):
    """Basic reputation checker for URL, IP, hashes, domains and log files."""

    refanged_ioc = utils.refang_ioc(ioc)

    # Check for single IoC input first
    if constants.IP_PATTERN.fullmatch(refanged_ioc):
        utils.process_single_ioc("Public IP", refanged_ioc)
    elif constants.URL_PATTERN.fullmatch(refanged_ioc):
        utils.process_single_ioc("URL", refanged_ioc)
    elif constants.HASH_PATTERN.fullmatch(ioc):
        utils.process_single_ioc("File hash", ioc)
    elif constants.DOMAIN_PATTERN.fullmatch(refanged_ioc):
        utils.process_single_ioc("Domain", refanged_ioc)

    # Check if input is a valid file existing on disk
    elif os.path.isfile(ioc):
        extension = pathlib.Path(ioc).suffix.lower()

        if extension not in constants.ALLOWED_EXTENSIONS:
            allowed_str = ", ".join(
                [ext.lstrip(".") for ext in constants.ALLOWED_EXTENSIONS]
            )
            print(
                f"Invalid file format: '{extension}'. Only {allowed_str} files are supported."
            )
            return

        # Process as log file
        # Avoid duplicated API requests for URL/domains by storing IoCs as (type, indicator) tuples
        found_iocs = set()
        found_domains = set()

        with open(ioc, "r", encoding="utf-8") as file:
            for line in file:
                # Refang found IoC first
                # Otherwise it will not read defanged IoCs in a log file
                clean_line = utils.refang_ioc(line)

                for match in constants.HASH_PATTERN.findall(line):
                    found_iocs.add(("File hash", match))
                for match in constants.URL_PATTERN.findall(clean_line):
                    found_iocs.add(("URL", match))
                for match in constants.IP_PATTERN.findall(clean_line):
                    found_iocs.add(("Public IP", match))
                for match in constants.DOMAIN_PATTERN.findall(clean_line):
                    found_domains.add(match)

        urls = {indicator for ioc_type,
                indicator in found_iocs if ioc_type == "URL"}

        for domain in found_domains:
            if any(domain in url for url in urls):
                continue  # Skip domain if already in found URL
            found_iocs.add(("Domain", domain))

        # Send API request for each unique IoC
        for ioc_type, indicator in found_iocs:
            utils.process_single_ioc(ioc_type, indicator)

        # Catch invalid single IoCs or non-existent files with file extensions
    elif "." in ioc and not any(
        ioc.endswith(extension) for extension in constants.ALLOWED_EXTENSIONS
    ):
        # For input like "nonexistent_file.php" or "test.php"
        allowed_str = ", ".join(
            [ext.lstrip(".") for ext in constants.ALLOWED_EXTENSIONS]
        )
        print(f"Invalid file format. Only {allowed_str} are allowed")
    else:
        print("Invalid input, try again.")


if __name__ == "__main__":
    check_reputation()  # noqa: E1120
