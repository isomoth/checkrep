# checkrep

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/isomoth/checkrep/blob/master/LICENSE)

A CLI tool to check the reputation of indicators of compromise (IP addresses, hashes, URLs and domains) as a single string, or parsed from a raw log.

Based on feedback and advice from Volvo SOC analysts from different levels, the application is a Proof of Concept for the partial automation of external IoC sweeps.

Currently, it fetches data from VirusTotal API and presents a simplified summary of the IoC report.

## Requirements

In order to fetch data from VirusTotal, an API key is needed. You can go to https://www.virustotal.com/gui/sign-in to get one.

## Installation

Install checkrep by using `pip`:

```bash
pip install git+https://github.com/isomoth/checkrep.git
```

Create a .env file in the checkrep/checkrep folder. The file should contain the following values:

```
API_KEY=<your-API-key>
API_BASE_URL=https://www.virustotal.com/api/v3/
IP_ADDRESS_ENDPOINT=ip_addresses/
URL_ADDRESS_ENDPOINT=urls/
HASH_ENDPOINT=files/
DOMAIN_ENDPOINT=domains/
```

## Usage

For help, run:

```bash
checkrep --help
```

You can also use:

```bash
python -m checkrep --help
```

The application takes two types of input:

A string in the form of an IP address, a file hash, a domain, or a URL. It can be sent as a flag:

```bash
checkrep --ioc 23[.]129[.]64[.]134
```

Or after a prompt:

```
checkrep

Enter a defanged IP address, URL, domain, file hash or log file path:
23[.]129[.]64[.]134
```

checkrep then sends an API-request to VirusTotal, fetches the report for the IoC and returns a simplified summary:

```
[MALICIOUS] Public IP 23.129.64.134 - Malicious: 12 | Suspicious: 5 | Clean: 74
```

The tool also accepts a raw log as a file path:

```bash
checkrep --ioc sample_network_log.txt
```

```bash
checkrep –-ioc /home/my-user/Downloads/sample_network_log_.txt
```

## Future Enhancements

Based on feedback from SOC-analysts, the following enhancements could be included in future versions of checkrep:

- A more complete threat summary, including the IoC relationships from the VirusTotal report and a selection of the most reputable vendors who have reported the IoC as malicious.
- More log formats.
- Integration of more aggregator services, since one single IoC aggregator such as VirusTotal does not provide the entire picture needed for decision making during alert analysis.
- GUI for better readability and usability.
- Generation of PDF reports.

## Upcoming improvements

- The application has undergone functional testing, but it needs automated tests.
- Security scans and a more thorough implementation of secure code practices are also needed.
- A few SonarQube alerts still need to be solved.
