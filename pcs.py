import argparse
import re
import os
import gzip
import shodan
import requests
import glob
import logging
import signal
import sys
import csv
import json
from datetime import datetime
import configparser
from tqdm import tqdm

config = configparser.ConfigParser()
config.read('api.conf')
api_shodan = config['API']['api_shodan']
api = shodan.Shodan(api_shodan)
targets = []

def setup_logging(logfile):
    logging.basicConfig(filename=logfile, filemode='a', format='%(asctime)s - %(message)s', level=logging.INFO)

def query_parse(start_ip, end_ip):
    ip_range = "{}-{}".format(start_ip, end_ip)
    query = 'ip:"{}"'.format(ip_range)
    return query

def get_nested_value(data, key):
    keys = key.split('.')
    for k in keys:
        data = data.get(k, None)
        if data is None:
            return None
    return data

def shodan_query(api_key, query):
    url = f'https://api.shodan.io/shodan/host/search?key={api_key}&query={query}'
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if isinstance(data, dict) and 'matches' in data and isinstance(data['matches'], list) and data['matches']:
            if args.csv:
                with open(f'{args.output}.csv', 'a', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    for match in data['matches']:
                        row = []
                        ip_str_value = str(match.get('ip_str', '')).encode('utf-8', errors='ignore').decode('utf-8')
                        row.append(f"ip_str: {ip_str_value}")
                        port_value = str(match.get('port', '')).encode('utf-8', errors='ignore').decode('utf-8')
                        row.append(f"port: {port_value}")
                        for key, value in match.items():
                            if key not in ['ip_str', 'port']:
                                if isinstance(value, dict):
                                    for sub_key, sub_value in value.items():
                                        if isinstance(sub_value, str):
                                            sanitized_value = sub_value.encode('utf-8', errors='ignore').decode('utf-8')
                                            row.append(f"{key}.{sub_key}: {sanitized_value}")
                                        else:
                                            row.append(f"{key}.{sub_key}: {sub_value}")
                                else:
                                    if isinstance(value, str):
                                        sanitized_value = value.encode('utf-8', errors='ignore').decode('utf-8')
                                        row.append(f"{key}: {sanitized_value}")
                                    else:
                                        row.append(f"{key}: {value}")
                        writer.writerow(row)
               
                
              
            if args.json:
                with open(f'{args.output}.json', 'a', encoding='utf-8') as jsonfile:
                    for match in data['matches']:
                        try:
                            json.dump(match, jsonfile, ensure_ascii=False, indent=4)
                            jsonfile.write('\n')
                        except UnicodeEncodeError:
                            pass
            fields_to_extract = [
    'ip_str', 'port', 'product', 'transport', 'version', 'data', 'os', 'cpe',
    'http.host', 'http.title', 'http.status', 'http.redirects', 'http.location',
    'http.html', 'vulns', 'isp', 'hostnames', 'org',
    'location.city', 'location.region_code', 'location.area_code',
    'location.longitude', 'location.latitude', 'location.country_code',
    'location.country_name'
                                ]
            essential_fields = ['org', 'ip_str', 'port', 'product', 'version', 'os', 'cpe']
            for match in data['matches']:
                row = []
                row.append("----------------------")
                if args.scan:
                    for field in essential_fields:
                        value = match.get(field, None)
                        if value:
                            if field == 'org':
                                row.append(f"Organization: {value}")
                            elif field == 'ip_str':
                                row.append(f"IP: {value}")
                            elif field == 'port':
                                row.append(f"Port: {value}")
                            elif field == 'product':
                                row.append(f"Product: {value}")
                            elif field == 'version':
                                row.append(f"Version: {value}")
                            elif field == 'os':
                                row.append(f"OS: {value}")
                            elif field == 'cpe':
                                row.append(f"CPE: {value}")
                    transport_value = match.get('transport', None)
                    if transport_value:
                        row.append(f"Protocol: {transport_value}")
                    vulns_value = match.get('vulns', None)
                    if vulns_value:
                        row.append(f"Vulns: ")
                        for cve, details in vulns_value.items():
                            row.append(f"- {cve}:")
                            for key, value in details.items():
                                if isinstance(value, list):
                                    row.append(f"    - {key}:")
                                    for item in value:
                                        row.append(f"        - {item}")
                                else:
                                    row.append(f"    - {key}: {value}")

                    if args.verbose:
                        log_and_print("\n ".join(row))
                    else:
                        logging.info("\n".join(row))

                else:
                    org_value = match.get('org', None)
                    if org_value: row.append(f"Organization: {org_value}")
                    isp_value = match.get('isp', None)
                    if isp_value: row.append(f"ISP: {isp_value}")
                    ip_str_value = match.get('ip_str', None)
                    if ip_str_value: row.append(f"IP: {ip_str_value}")
                    port_value = match.get('port', None)
                    if port_value: row.append(f"Port: {port_value}")
                    product_value = match.get('product', None)
                    if product_value: row.append(f"Product: {product_value}")
                    transport_value = match.get('transport', None)
                    if transport_value: row.append(f"Protocol: {transport_value}")
                    version_value = match.get('version', None)
                    if version_value: row.append(f"Version: {version_value}")
                    os_value = match.get('os', None)
                    if os_value: row.append(f"OS: {os_value}")
                    cpe_value = match.get('cpe', None)
                    if cpe_value: row.append(f"CPE: {cpe_value}")
                    hostnames_value = match.get('hostnames', None)
                    if hostnames_value: row.append(f"hostnames: {hostnames_value}")
                    location_city_value = get_nested_value(match, 'location.city')
                    if location_city_value: row.append(f"Location City: {location_city_value}")
                    location_region_code_value = get_nested_value(match, 'location.region_code')
                    if location_region_code_value: row.append(f"Location region code: {location_region_code_value}")
                    location_area_code_value = get_nested_value(match, 'location.area_code')
                    if location_area_code_value: row.append(f"Location area code: {location_area_code_value}")
                    location_longitude_value = get_nested_value(match, 'location.longitude')
                    if location_longitude_value: row.append(f"Location longitude: {location_longitude_value}")
                    location_latitude_value = get_nested_value(match, 'location.latitude')
                    if location_latitude_value: row.append(f"Location latitude: {location_latitude_value}")
                    location_country_code_value = get_nested_value(match, 'location.country_code')
                    if location_country_code_value: row.append(f"Location country code: {location_country_code_value}")
                    location_country_name_value = get_nested_value(match, 'location.country_name')
                    if location_country_name_value: row.append(f"Location country name: {location_country_name_value}")
                    data_value = match.get('data', None)
                    if data_value: row.append(f"Data:\n###########\n {data_value}\n###########")
                    http_host_value = get_nested_value(match, 'http.host')
                    if http_host_value: row.append(f"HTTP host: {http_host_value}")
                    http_title_value = get_nested_value(match, 'http.title')
                    if http_title_value: row.append(f"HTTP Title: {http_title_value}")
                    http_status_value = get_nested_value(match, 'http.status')
                    if http_status_value: row.append(f"HTTP Status: {http_status_value}")
                    http_redirects_value = get_nested_value(match, 'http.redirects')
                    if http_redirects_value: row.append(f"HTTP Redirects: {http_redirects_value}")
                    http_location_value = get_nested_value(match, 'http.location')
                    if http_location_value: row.append(f"HTTP Location: {http_location_value}")
                    http_html_value = get_nested_value(match, 'http.html')
                    if http_html_value: row.append(f"HTTP Data: {http_html_value}")
                    vulns_value = match.get('vulns', None)
                    if vulns_value: 
                        row.append(f"Vulns: ")
                        for cve, details in vulns_value.items():
                            row.append(f"- {cve}:")
                            for key, value in details.items():
                                if isinstance(value, list):
                                    row.append(f"    - {key}:")
                                    for item in value:
                                        row.append(f"        - {item}")
                                else:
                                    row.append(f"    - {key}: {value}")
                    if args.verbose:
                        log_and_print("\n ".join(row))
                    else:
                        logging.info("\n".join(row))
        else:
            pass
    else:
        print(f"Connection error: {response.status_code}, check the API key or connectivity. Exiting program...")
        logging.info(f"Connection error: {response.status_code}, check the API key or connectivity. Exiting program...")
        exit()

def write_to_csv(data_dict):
    fieldnames = sorted(data_dict.keys())
    with open(f'{args.output}.csv', 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if csvfile.tell() == 0:
            writer.writeheader()
        writer.writerow(data_dict)

def write_to_json(data_dict):
    with open(f'{args.output}.json', 'a', encoding='utf-8') as jsonfile:
        json.dump(data_dict, jsonfile, ensure_ascii=False, indent=4)
        jsonfile.write('\n')

def process_file(file_path, target_regex):
    log_and_print(f"Processing {file_path}...")
    try:
        with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            matches = re.finditer(r'(?s)inetnum:(.*?)(?=\ninetnum:|\Z)', content)
            for match in matches:
                data_str = match.group(1)
                data = {}
                inetnum_match = "".join(data_str.split("inetnum:")[0:]).strip()
                inetnum_match = "".join(inetnum_match.split("\n")[0])
                if inetnum_match:
                    data['inetnum'] = inetnum_match
                descr_matches = re.findall(r'descr:\s+(.+)', data_str)
                if descr_matches:
                    data['descr'] = '\n'.join(descr_matches)
                country_match = re.search(r'country:\s+(.+)', data_str)
                if country_match:
                    data['country'] = country_match.group(1)
                mnt_by_match = re.search(r'mnt-by:\s+(.+)', data_str)
                if mnt_by_match:
                    data['mnt-by'] = mnt_by_match.group(1)
                last_modified_match = re.search(r'last-modified:\s+(.+)', data_str)
                if last_modified_match:
                    data['last-modified'] = last_modified_match.group(1)
                if data:
                    if filter_target(data, target_regex):
                        range_start = "".join(data["inetnum"].split("-")[0]).strip()
                        range_stop = "".join(data["inetnum"].split("-")[1]).strip()
                        range_ip = query_parse(range_start, range_stop)
                        shodan_query(api_shodan, range_ip)
    except EOFError:
        print(f"Error processing {file_path}: Compressed file ended before the end-of-stream marker was reached.")
        print("Please consider downloading the database files again (--update).")
        logging.info(f"Error processing {file_path}: Compressed file ended before the end-of-stream marker was reached.")
        logging.info("Please consider downloading the database files again (--update).")

def download_file(url, filename):
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024
    with open(filename, 'wb') as f, tqdm(
        total=total_size,
        unit='B', unit_scale=True,
        desc=filename.split('/')[-1]
    ) as pbar:
        for data in response.iter_content(block_size):
            f.write(data)
            pbar.update(len(data))

def download_files(update=False):
    files_to_download = [
        ("https://ftp.afrinic.net/pub/dbase/afrinic.db.gz", "ripe_db/afrinic.db.gz"),
        ("https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz", "ripe_db/apnic.db.inetnum.gz"),
        ("https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz", "ripe_db/ripe.db.inetnum.gz"),
        ("https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz", "ripe_db/ripe.db.inet6num.gz")
    ]
    for url, filename in files_to_download:
        if update or not os.path.exists(filename) or not is_file_recent(filename):
            print(f"Downloading {filename}...")
            logging.info(f"Downloading {filename}...")
            try:
                download_file(url, filename)
                print(f"Download of {filename} completed.")
                logging.info(f"Download of {filename} completed.")
            except Exception as e:
                print(f"Error downloading {filename}: {e}")
                logging.info(f"Error downloading {filename}: {e}")
                continue

def is_file_recent(filename):
    file_time = datetime.fromtimestamp(os.path.getmtime(filename))
    return (datetime.now() - file_time).days < 7

def filter_target(data, target_regex):
    for key, value in data.items():
        if isinstance(value, str):
            if re.search(target_regex, value, re.IGNORECASE):
                return True
    return False

def handle_sigint(signum, frame):
    print('Program execution interrupted.')
    logging.info('Program execution interrupted.')
    sys.exit(0)

def log_and_print(message):
    logging.info(message)
    if args.verbose:
        try:
            print(message)
        except UnicodeEncodeError:
            pass

if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_sigint)
    parser = argparse.ArgumentParser(
        description='Passive Company Scanner: Script for passive perimeter search, open ports, vulnerabilities, and geographical information on an organization\'s infrastructure.',
        usage='python3 passive_company_scanner.py --update -r "\\bcompany" -v',
        epilog='Example: python3 passive_company_scanner.py --update -r "\\bcompany" -v -j -c -o output_filename')
    parser.add_argument('--update', action='store_true', help='Update files in the ripe_db directory')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    parser.add_argument('-r', '--regex', type=str, help='Target Regex example: -r "\\bcompany"')
    parser.add_argument('-c', '--csv', action='store_true', help='Write results to a CSV file')
    parser.add_argument('-j', '--json', action='store_true', help='Write results to a JSON file')
    parser.add_argument('-o', '--output', type=str, default='output', help='Base name for output files (log, csv, json)')
    parser.add_argument('-s', '--scan', action='store_true', help='Prints or logs only essential scan information: IP, port, version and product, operating system, CPE, and vulnerabilities (CSV and JSON files remain complete).')
    args = parser.parse_args()
    setup_logging(f'{args.output}.log')

    gzip_files = glob.glob("ripe_db/*.gz")
    if not gzip_files:
        response = input("Local files are missing. Do you want to download them? (Y/N): ").strip().lower()
        if response == 'y':
            download_files(update=False)
        else:
            print("No files to process. Exiting.")
            sys.exit(0)
    else:
        all_recent = all(is_file_recent(file) for file in gzip_files)
        if not all_recent:
            response = input("Local files are not up to date. Do you want to download the update? (Y/N): ").strip().lower()
            if response == 'y':
                download_files(update=True)

    if not args.update and not args.regex:
        parser.error('The --update option can be used alone, but the -r option is required for scanning.')
    
    log_and_print(f"Found {len(gzip_files)} files to process.")
    print("Scan started, please wait...")
    for file in gzip_files:
        process_file(file, args.regex)
    print("Processing completed.")
