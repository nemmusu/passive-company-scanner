# Passive Company Scanner

## Overview

The Passive Company Scanner, by inputting a regex containing the company name (for example: \bcompany), utilizes data from the RIPE db to identify involved networks and leverages the Shodan API to retrieve detailed information about the identified IP addresses, thereby conducting a passive perimeter search, discovering open ports, and identifying potential vulnerabilities in the organization's infrastructure.
It uses non-invasive techniques to map the attack surface without directly interacting with the targets. 

## Requirements

-   Python 3.x
-   Shodan API
-   Python Modules: `shodan`, `tqdm`
-   To install dependencies, run: `pip3 install -r requirements.txt`

## Installation

1.  Clone or download the repository.
2.  Make sure you have all the above requirements installed.
3.  Modify the `api.conf` file with your Shodan API key.
4.  Run the script using the command `python3 passive_company_scanner.py` followed by desired options.

## Usage

-   `--update`: Update files in the `ripe_db` directory.The `--update` command is required on the first run to download the RIPE db.  It is highly recommended to update the RIPE database to the latest version before each usage to ensure greater precision in the results.
-   `-v`, `--verbose`: Enable verbose mode.
-   `-r`, `--regex`: Target Regex (example: `-r "\\bcompany"`).
-   `-c`, `--csv`: Write results to a CSV file.
-   `-j`, `--json`: Write results to a JSON file.
-   `-o`, `--output`: Base name for output files (log, csv, json).
-   `-s`, `--scan`: Prints or logs only essential scan information: IP, port, version and product, operating system, CPE, and vulnerabilities (CSV and JSON files remain complete).

## Example

bash

```bash
python3 passive_company_scanner.py --update -r "\\bcompany" -v -j -c -o output_filename
```