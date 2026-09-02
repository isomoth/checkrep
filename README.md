# checkrep

[![PyPI](https://img.shields.io/pypi/v/checkrep.svg)](https://pypi.org/project/checkrep/)
[![Changelog](https://img.shields.io/github/v/release/isomoth/checkrep?include_prereleases&label=changelog)](https://github.com/isomoth/checkrep/releases)
[![Tests](https://github.com/isomoth/checkrep/actions/workflows/test.yml/badge.svg)](https://github.com/isomoth/checkrep/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/isomoth/checkrep/blob/master/LICENSE)

Check reputation for indicators of compromise

## Installation

Install this tool using `pip`:
```bash
pip install checkrep
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
## Development

To contribute to this tool, first checkout the code. Then create a new virtual environment:
```bash
cd checkrep
python -m venv venv
source venv/bin/activate
```
Now install the dependencies and test dependencies:
```bash
pip install -e '.[test]'
```
To run the tests:
```bash
python -m pytest
```
