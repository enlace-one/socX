#!/usr/bin/env python3

try:
    import argparse
    import os
    import time
    import re
    import socket
    import hashlib
    import requests
    import sqlite3 as sql
    import pandas as pd
    import keyring
    import xml.etree.ElementTree as ET
    from pathlib import Path

    try:
        from . import util
    except:
        import util
except ImportError as e:
    print(
        f"""You are missing a required module ({e.name})
Try installing it with:
    pip install {e.name}
or
    python -m pip install {e.name} --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org"""
    )
    exit(1)


program_name = "socx"
VERSION = 1.1
about = f"""
   _____ ____  _______  __
  / ___// __ \/ ____/ |/ /
  \__ \/ / / / /    |   / 
 ___/ / /_/ / /___ /   |  
/____/\____/\____//_/|_|  

Version: {VERSION}
A tool to assist with day to day activites in a security operations center (pronounced "socks")
"""

usage = f"""Usage:
    {program_name} [universal options] [function] [options]
    python {program_name}.py [universal options] [function] [options]
        
Examples:
    {program_name} --help
    {program_name} info -h
    {program_name} info -ip 1.2.3.4
    {program_name} -v 3 info -d google.com
    {program_name} search -f filename.txt -i
    {program_name} search -f fold.*name -r
    {program_name} tools --url_unwrap "https://urldefense.com/v3/__https:/..."
    
"""


def unwrap_url(url):
    pp_decoder = util.URLDefenseDecoder()
    url = pp_decoder.decode(url)
    if "safelinks" in url:
        url = url.split("url=")[1]
    url = pp_decoder.decode(url)
    return url


def main():
    parser = argparse.ArgumentParser(prog=program_name, description=about, usage=usage)
    subparsers = parser.add_subparsers(dest="function", help="Function to perform")

    # Universal Arguments
    parser.add_argument(
        "-v",
        "--verbosity",
        type=int,
        default=1,
        help="The verbosity, 0 for quiet, 5 for very verbose",
    )

    # Config - Edit stored settings
    config = subparsers.add_parser(
        "config", help="Edit the settings, keys, and variables"
    )

    # Information - Online
    info = subparsers.add_parser(
        "info", help="Gather information on the specified topic"
    )
    info.add_argument("-ip", "--ip", type=str, help="An IP address")
    info.add_argument("-d", "--domain", type=str, help="A domain (google.com)")
    info.add_argument("-url", "--url", type=str, help="A url")
    # add URL, Hash?

    # Search - Local
    search = subparsers.add_parser(
        "search", help="Search this machine for the specified topic"
    )
    search.add_argument("-f", "--filename", type=str, help="A file or folder name")
    search.add_argument(
        "-r", "--regex", action="store_true", help="The query is a regex pattern"
    )
    search.add_argument(
        "-a",
        "--find_all",
        action="store_true",
        help="Find all occurances (default is find first)",
    )
    search.add_argument(
        "-i",
        "--insensitive",
        action="store_true",
        help="Search case insensitive (default is case sensitive)",
    )
    # Filename, Hash, registrykey?

    # Tools - Local
    tools = subparsers.add_parser("tools", help="Use tools to perform a function")
    tools.add_argument(
        "-url",
        "--url_unwrap",
        type=str,
        help="A URL to unwrap (remove safelinks and protectlinks)",
    )
    tools.add_argument(
        "-cmd",
        "--cmdhistory",
        action="store_true",
        help="Gathers the available command history to the current directory",
    )
    tools.add_argument(
        "-browsers",
        "--browserhistory",
        action="store_true",
        help="Gathers the available browser history, etc to the current directory",
    )
    tools.add_argument(
        "-u",
        "--user",
        type=str,
        default="~",
        help="The user's name to use. Default is current user.",
    )
    tools.add_argument(
        "-r",
        "--regex",
        action="store_true",
        help="Launch a regex testing environment.",
    )
    tools.add_argument(
        "-c",
        "--csvs",
        type=int,
        default=0,
        help="Combine the last X modified csvs in the current directory. Enter 1 for walkthrough",
    )

    args = parser.parse_args()

    ##########
    ## Util ##
    ##########

    def p(*args_, v=1, end="\n", sep=" ", file=None):
        if args.verbosity >= v:
            print(*args_, end=end, sep=sep, file=file)

    ############
    ## Config ##
    ############

    environmental_variables = {
        "InsightVMAPI_BASE_URL": "",
        "InsightVMAPI_KEY": "",
        "VirusTotalAPI_KEY": "",
    }

    def get_enironmental_variable(name):
        value = keyring.get_password("system", "_socX__" + name)
        if value is None:
            value = environmental_variables[name]
        return value

    if args.function == "config":
        while True:
            p("Settings, keys, variables", v=1)
            for index, var in enumerate(environmental_variables.keys()):
                print(f"\t{index} - {var}")
            index = input(
                "Enter the index of the variable you want to edit (Nothing to stop): "
            )
            if index == "":
                break
            else:
                index = int(index)
            p(f"Editing '{list(environmental_variables.keys())[index]}'", v=1)
            old_value = get_enironmental_variable(
                list(environmental_variables.keys())[index]
            )
            print(f"Old value:'{old_value}'")
            new_value = input("New value (Nothing to cancel): ")
            if new_value == "":
                continue
            print("_socX__" + list(environmental_variables.keys())[index])
            keyring.set_password(
                "system",
                "_socX__" + list(environmental_variables.keys())[index],
                new_value,
            )
            p("Value updated\n", v=1)

    ##########
    ## Info ##
    ##########

    def print_ip_info(ip):
        # try:
        #     response = requests.request("GET", url=f"https://ipinfo.io/{args.ip}/json")
        #     ip_service = "ipinfo"
        # except:
        #     p("Failed to get information from ipinfo.io", v=3)
        #     response = requests.request("GET", url=f"http://ipwho.is/{args.ip}")
        #     ip_service = "ipwhois"
        # for key, item in response.json().items():
        #     if args.verbosity > 0:
        #         print(f"({ip_service}) {key}: {item}")
        #     else:
        #         print(f"{key}: {item}")
        url = f"https://whois.arin.net/rest/ip/{ip}"
        ip_xml = requests.request("GET", url=url).text
        namespaces = {"ns": "https://www.arin.net/whoisrws/core/v1"}
        organization_url = ET.fromstring(ip_xml).find("ns:orgRef", namespaces).text
        org_xml = requests.request("GET", url=organization_url).text
        root = ET.fromstring(org_xml)
        org_name = root.find("ns:name", namespaces).text
        org_city = root.find("ns:city", namespaces).text
        org_country = root.find("ns:iso3166-1/ns:name", namespaces).text
        org_handle = root.find("ns:handle", namespaces).text
        registration_date = root.find("ns:registrationDate", namespaces).text

        print(f"(whois) Organization: {org_name}")
        print(f"(whois) Country: {org_country}")
        print(f"(whois) City: {org_city}")
        print(f"(whois) Handle: {org_handle}")
        print(f"(whois) Registration Date: {registration_date}")

    if args.function == "info":
        if args.ip:
            p(f"Getting information on {args.ip}", v=1)
            try:
                hostname = socket.gethostbyaddr(args.ip)
                print(f"Hostname: {hostname}")
            except Exception as e:
                p(f"Hostname: Error - {e}", v=1)
            # WINDOWS SPECIFIC
            ping_response = os.system(f"ping -n 1 {args.ip} > nul")
            if ping_response == 0:
                print(f"Ping: {args.ip} is up")
            else:
                print(f"Ping: {args.ip} is down")
            print_ip_info(args.ip)
            # Rapid7
            if (
                get_enironmental_variable("InsightVMAPI_BASE_URL") != ""
                and get_enironmental_variable("InsightVMAPI_KEY") != ""
            ):
                ivm = util.InsightVM(
                    get_enironmental_variable("InsightVMAPI_BASE_URL"),
                    get_enironmental_variable("InsightVMAPI_KEY"),
                )
                for asset in ivm.ip_search(args.ip):
                    print(ivm._format_return_string(asset))
        elif args.domain:
            if args.domain.startswith("http"):
                args.domain = args.domain.split("//")[1]
            if args.domain.startswith("www."):
                args.domain = args.domain.split("www.")[1]
            p(f"Getting information on {args.domain}", v=1)
            try:
                ip = socket.gethostbyname(args.domain)
                print(f"IP: {ip}")
            except Exception as e:
                p(f"IP: Error - {e}", v=1)
            # WINDOWS SPECIFIC
            ping_response = os.system(f"ping -n 1 {args.domain} > nul")
            if ping_response == 0:
                print(f"Ping: {args.domain} is up")
            else:
                print(f"Ping: {args.domain} is down")

            print_ip_info(ip)
            print(f"Whois record: https://www.whois.com/whois/{args.domain}")

        elif args.url:
            url = unwrap_url(args.url)

            # Virus total post url
            vt_api_key = get_enironmental_variable("VirusTotalAPI_KEY")
            vt_report_url = ""
            if vt_api_key != "":
                response = requests.request(
                    "POST",
                    url="https://www.virustotal.com/api/v3/urls",
                    headers={"x-apikey": vt_api_key},
                    data={"url": url},
                )
                vt_report_url = response.json()["data"]["links"]["self"]

            p(f"Getting information on {url} (unwrapped)", v=1)

            # Virus total get url
            if vt_api_key != "":
                p("Waiting for Virustotal to process..", v=3)
                for seconds in [5, 7, 10, 15]:
                    time.sleep(seconds)
                    report_response = requests.request(
                        "GET", url=vt_report_url, headers={"x-apikey": vt_api_key}
                    ).json()
                    if report_response["data"]["attributes"]["status"] != "queued":
                        print("Virustotal:", report_response["data"]["links"]["item"])
                        print(
                            "Virustotal:",
                            report_response["data"]["attributes"]["stats"],
                        )
                        p("P.S. Run again if stats are incomplete now.", v=3)
                        break

    ############
    ## Search ##
    ############

    def search(pattern, string):
        if args.insensitive:
            return re.search(pattern, string, re.IGNORECASE)
        else:
            return re.search(pattern, string)

    def find_file(filename, directory=os.getcwd(), find_all=False):
        files_found = []
        filename_copy = filename
        if args.insensitive and not args.regex:
            filename = filename.lower()
        for root, dirs, files in os.walk(directory):
            if args.regex:
                r_files = [
                    os.path.join(root, file)
                    for file in files + dirs
                    if search(filename, file)
                ]
                if find_all:
                    files_found.extend(r_files)
                elif len(r_files) > 0:
                    return r_files[0]
            else:
                if args.insensitive:
                    files = [file.lower() for file in files]
                    dirs = [dir.lower() for dir in dirs]
                if filename in files or filename in dirs:
                    if find_all:
                        files_found.append(os.path.join(root, filename_copy))
                    else:
                        return os.path.join(root, filename_copy)

        if find_all:
            return files_found
        else:
            return None

    if args.function == "search":
        if args.filename:
            p(f"Searching for {args.filename}", v=1)
            if args.insensitive:
                p("Performing case insensitive search", v=3)
            if args.find_all:
                p("Finding all occurances", v=3)
            # WINDOWS SPECIFIC
            if args.find_all:
                result = find_file(args.filename, "C:\\", True)
                result = result + find_file(args.filename, "D:\\", True)
                result = set(result)
                if len(result) == 0:
                    print("File/Folder not found")
                else:
                    for file in result:
                        print(f"File/Folder found at {file}")
            else:
                result = find_file(args.filename, os.path.dirname(os.getcwd()))
                if result is None:
                    result = find_file(args.filename, os.path.expanduser("~"))
                if result is None:
                    result = find_file(args.filename, "C:\\")
                if result is None:
                    result = find_file(args.filename, "D:\\")
                if result is None:
                    print("File/Folder not found")
                else:
                    print(f"File/Folder found at {result}")

        elif args.hash:
            p(f"Searching for {args.hash}", v=1)
            # WINDOWS SPECIFIC

            def calculate_hash(file_path, algorithm="sha256"):
                """Calculate the hash of a file."""
                hash_func = getattr(hashlib, algorithm.lower(), None)
                if hash_func is None:
                    raise ValueError(f"Invalid hash algorithm: {algorithm}")

                # Read the file in binary mode and compute the hash
                with open(file_path, "rb") as f:
                    hash_obj = hash_func()
                    while chunk := f.read(4096):  # Read in chunks to handle large files
                        hash_obj.update(chunk)

                return hash_obj.hexdigest()

            def search_hash(file_path, target_hash, algorithm="sha256"):
                """Search for a specific hash in a file."""
                file_hash = calculate_hash(file_path, algorithm)
                return file_hash == target_hash

            # Example usage:
            file_path = "path/to/your/file"
            target_hash = "put your target hash here"
            algorithm = "sha256"  # Specify the hashing algorithm if needed

            if search_hash(file_path, target_hash, algorithm):
                print("Hash found in the file.")
            else:
                print("Hash not found in the file.")

    ###########
    ## Tools ##
    ###########
    if args.function == "tools":
        # Test Link: https://urldefense.com/v3/__https:/conferences.stjude.org/g87vv8?i=2NejfAgCkki403xbcRpHuw&locale=en-US__;!!NfcMrC8AwgI!cq3afLDXviFyix2KeJ62VsQBrrZOgfyZu1fks7uQorRGX6VOgcDaUgTpxFdJRmXMdtU5zsmZB9PUw-TmquYgbIGIYUDPsQ$
        # Test Link:
        if args.url_unwrap:
            p("Unwrapping URL\n", v=3)
            print(f"Unwrapped URL:\n{unwrap_url(args.url_unwrap)}")
            p("\n", v=3)

        elif args.browserhistory:
            p("Gathering browser history. Will output to cwd", v=3)
            p(
                "You may want to close the browser before running this, otherwise you may get 'database is locked' errors",
                v=5,
            )
            browser_history_paths = [
                {
                    "path": "/AppData/Local/Google/Chrome/User Data/Default/",
                    "browser": "Chrome",
                    "databases": [
                        "History",
                        "Cookies",
                        "Vistied Links",
                        "Web Data",
                        "Shortcuts",
                        "Top Sites",
                        "Favicons",
                        "Network Action Predictor",
                    ],
                },
                {
                    "browser": "Brave",
                    "path": "/AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/",
                    "databases": [
                        "History",
                        "Cookies",
                        "Vistied Links",
                        "Web Data",
                        "Shortcuts",
                        "Top Sites",
                        "Favicons",
                        "Network Action Predictor",
                    ],
                },
                {
                    "browser": "FireFox",
                    "path": "/AppData/Roaming/Mozilla/Firefox/Profiles/",
                    "databases": [
                        "formhistory.sqlite",
                        "favicons.sqlite",
                        "places.sqlite",
                        "cookies.sqlite",
                    ],
                },
                {
                    "browser": "Edge",
                    "path": "/AppData/Local/Microsoft/Edge/User Data/Default/",
                    "databases": [
                        "History",
                        "Visited Links",
                        "Shortcuts",
                        "Top Sites",
                        "Bookmarks",
                    ],
                },
            ]
            for browser in browser_history_paths:
                folder = os.path.expanduser(args.user) + browser["path"]
                if os.path.exists(folder):
                    p(f"Found {browser['browser']} at {folder}", v=5)
                    os.makedirs(browser["browser"], exist_ok=True)
                    for name in browser["databases"]:
                        if os.path.exists(folder + name):
                            try:
                                p(f"Found {name} at {folder}", v=5)
                                con = sql.connect(folder + name)
                                cursor = con.cursor()
                                cursor.execute(
                                    "SELECT name FROM sqlite_schema WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY 1;"
                                )
                                for i in cursor.fetchall():
                                    table = i[0]
                                    df = pd.read_sql(f"SELECT * FROM {table}", con)
                                    df.to_csv(f"{browser['browser']}/{table}.csv")

                                con.close()
                            except Exception as e:
                                p(f"Error with {name} - {e}", v=3)

        elif args.csvs:
            p("Starting combine CSVs", v=5)

            paths = sorted(Path().iterdir(), key=os.path.getmtime)
            paths.reverse()

            if args.csvs < 2:
                accum = 1
                p("File Paths", v=3)
                for path in paths:
                    if str(path).endswith(".csv"):
                        p(f"{accum} - {path}")
                        accum += 1
                csvs = int(input("Enter the index of the last CSV to include:"))
            else:
                csvs = args.csvs

            # Get File Paths
            file_paths = []
            for path in paths:
                if str(path).endswith(".csv"):
                    file_paths.append(str(path))
                    p(f"Added {path}", v=4)
                    csvs -= 1
                    if csvs == 0:
                        break
            dfs = []
            for path in file_paths:
                df = pd.read_csv(path)
                dfs.append(df)
            df = pd.concat(dfs)
            df.to_csv("COMBINED_FILE.csv", index=False)
            p("Outputed to COMBINED_FILE.csv", v=3)

        elif args.cmdhistory:
            p("Gathering command history. Will output to cwd.", v=3)
            cwd = os.getcwd()
            # Windows specific
            cmd_history_path = (
                os.path.expanduser(args.user)
                + "/AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
            )
            with open(cmd_history_path, "r") as file:
                with open(cwd + "\\powershell_history.txt", "w") as output_file:
                    for line in file:
                        output_file.write(line)
            p("Command history gathered", v=3)

        elif args.regex:
            to_match_list = []

            def append_matches():
                while True:
                    to_match = input("Enter text to match (nothing to stop):")
                    if to_match == "":
                        break
                    to_match_list.append(to_match)

            to_fail_list = []

            def append_failures():
                while True:
                    to_fail = input("Enter text to fail (nothing to stop):")
                    if to_fail == "":
                        break
                    to_fail_list.append(to_fail)

            def run_tests():
                while True:
                    success = True
                    regex = input("Enter regex to test (nothing to stop):")
                    if regex == "":
                        break
                    for to_match in to_match_list:
                        if not re.search(regex, to_match):
                            p(f"Failed to match: {to_match}")
                            success = False
                    for to_fail in to_fail_list:
                        if re.search(regex, to_fail):
                            p(f"Failed by matching: {to_fail}")
                            success = False
                    if success:
                        p("SUCCESS")

            append_matches()
            append_failures()
            run_tests()

    if not args.function:
        print(f"You must provide a function.")
        print(usage)


if __name__ == "__main__":
    main()
