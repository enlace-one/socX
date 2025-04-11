#!/usr/bin/env python3

from contextlib import suppress


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

#############
# Constants #
#############

PROGRAM_NAME = "socx"
VERSION = 1.1
ABOUT = f"""
   _____ ____  _______  __
  / ___// __ \/ ____/ |/ /
  \__ \/ / / / /    |   / 
 ___/ / /_/ / /___ /   |  
/____/\____/\____//_/|_|  

Version: {VERSION}
A tool to assist with day to day activites in a security operations center (pronounced "socks")
"""

USAGE = f"""Usage:
    {PROGRAM_NAME} [universal options] [function] [options]
    python {PROGRAM_NAME}.py [universal options] [function] [options]
        
Examples:
    {PROGRAM_NAME} --help
    {PROGRAM_NAME} info -h
    {PROGRAM_NAME} info -ip 1.2.3.4
    {PROGRAM_NAME} -v 3 info -d google.com
    {PROGRAM_NAME} search -f filename.txt -i
    {PROGRAM_NAME} search -f fold.*name -r
    {PROGRAM_NAME} tools --url_unwrap "https://urldefense.com/v3/__https:/..."
    
"""

#############
# Variables #
#############

verbosity = 1
case_insensitive = True
is_regex = False
find_all = False
user = ""

environmental_variables = {
    "InsightVMAPI_BASE_URL": "",
    "InsightVMAPI_KEY": "",
    "VirusTotalAPI_KEY": "",
}

##################
# Util Functions #
##################


def p(*args_, v=1, end="\n", sep=" ", file=None):
    if verbosity >= v:
        print(*args_, end=end, sep=sep, file=file)


def unwrap_url(url):
    pp_decoder = util.URLDefenseDecoder()
    url = pp_decoder.decode(url)
    if "safelinks" in url:
        url = url.split("url=")[1]
    url = pp_decoder.decode(url)
    return url


def search(pattern, string):
    if case_insensitive:
        return re.search(pattern, string, re.IGNORECASE)
    else:
        return re.search(pattern, string)


def find_file(filename, directory=os.getcwd(), find_all=False):
    files_found = []
    filename_copy = filename
    if case_insensitive and not is_regex:
        filename = filename.lower()
    for root, dirs, files in os.walk(directory):
        if is_regex:
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
            if case_insensitive:
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


def print_ip_info(ip):
    """Input IP address and prints whois on it"""
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


def get_enironmental_variable(name):
    value = keyring.get_password("system", "_socX__" + name)
    if value is None:
        value = environmental_variables[name]
    return value


#####################
# Primary Functions #
#####################


def do_config():
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


def do_ip_info(ip):
    p(f"Getting information on {ip}", v=1)
    try:
        hostname = socket.gethostbyaddr(ip)
        print(f"Hostname: {hostname}")
    except Exception as e:
        p(f"Hostname: Error - {e}", v=1)
    # WINDOWS SPECIFIC
    ping_response = os.system(f"ping -n 1 {ip} > nul")
    if ping_response == 0:
        print(f"Ping: {ip} is up")
    else:
        print(f"Ping: {ip} is down")
    print_ip_info(ip)
    # Rapid7
    if (
        get_enironmental_variable("InsightVMAPI_BASE_URL") != ""
        and get_enironmental_variable("InsightVMAPI_KEY") != ""
    ):
        ivm = util.InsightVM(
            get_enironmental_variable("InsightVMAPI_BASE_URL"),
            get_enironmental_variable("InsightVMAPI_KEY"),
        )
        for asset in ivm.ip_search(ip):
            print(ivm._format_return_string(asset))


def do_domain_info(domain):
    if domain.startswith("http"):
        domain = domain.split("//")[1]
    if domain.startswith("www."):
        domain = domain.split("www.")[1]
    p(f"Getting information on {domain}", v=1)
    try:
        ip = socket.gethostbyname(domain)
        print(f"IP: {ip}")
    except Exception as e:
        p(f"IP: Error - {e}", v=1)
    # WINDOWS SPECIFIC
    ping_response = os.system(f"ping -n 1 {domain} > nul")
    if ping_response == 0:
        print(f"Ping: {domain} is up")
    else:
        print(f"Ping: {domain} is down")

    print_ip_info(ip)
    print(f"Whois record: https://www.whois.com/whois/{domain}")


def do_url_info(url):
    url = unwrap_url(url)

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


def do_filename_search(filename):
    p(f"Searching for {filename}", v=1)
    if case_insensitive:
        p("Performing case insensitive search", v=3)
    if find_all:
        p("Finding all occurances", v=3)
    # WINDOWS SPECIFIC
    if find_all:
        result = find_file(filename, "C:\\", True)
        result = result + find_file(filename, "D:\\", True)
        result = set(result)
        if len(result) == 0:
            print("File/Folder not found")
        else:
            for file in result:
                print(f"File/Folder found at {file}")
    else:
        result = find_file(filename, os.path.dirname(os.getcwd()))
        if result is None:
            result = find_file(filename, os.path.expanduser("~"))
        if result is None:
            result = find_file(filename, "C:\\")
        if result is None:
            result = find_file(filename, "D:\\")
        if result is None:
            print("File/Folder not found")
        else:
            print(f"File/Folder found at {result}")


def do_url_unwrap(url):
    p("Unwrapping URL\n", v=3)
    print(f"Unwrapped URL:\n{unwrap_url(url)}")
    p("\n", v=3)


def do_browser_history():
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
        folder = os.path.expanduser(user) + browser["path"]
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


def do_combine_csvs(csvs=0):
    p("Starting combine CSVs", v=5)
    paths = sorted(Path().iterdir(), key=os.path.getmtime)
    paths.reverse()

    if csvs < 2:
        accum = 1
        p("File Paths", v=3)
        for path in paths:
            if str(path).endswith(".csv"):
                p(f"{accum} - {path}")
                accum += 1
        csvs = int(input("Enter the index of the last CSV to include:"))

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


def do_command_history():
    p("Gathering command history. Will output to cwd.", v=3)
    cwd = os.getcwd()
    # Windows specific
    cmd_history_path = (
        os.path.expanduser(user)
        + "/AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
    )
    with open(cmd_history_path, "r") as file:
        with open(cwd + "\\powershell_history.txt", "w") as output_file:
            for line in file:
                output_file.write(line)
    p("Command history gathered", v=3)


####################
# Interactive Mode #
####################


def interactive_mode():
    functions = [
        {"name": "Edit SOCX Config", "function": do_config, "arguments": []},
        {
            "name": "Combine CSVs",
            "function": do_combine_csvs,
            "arguments": [],  # Will prompt if blank
        },
        {
            "name": "Unwrap a URLDefense URL",
            "function": do_url_unwrap,
            "arguments": [{"name": "url", "prompt": "Enter the URL: ", "type": str}],
        },
        {
            "name": "Get info on a URL",
            "function": do_url_info,
            "arguments": [{"name": "url", "prompt": "Enter the URL: ", "type": str}],
        },
        {
            "name": "Get info on a domain",
            "function": do_domain_info,
            "arguments": [
                {"name": "domain", "prompt": "Enter the domain: ", "type": str}
            ],
        },
        {
            "name": "Get info on an ip",
            "function": do_ip_info,
            "arguments": [{"name": "ip", "prompt": "Enter the ip: ", "type": str}],
        },
        {
            "name": "Find a file",
            "function": do_filename_search,
            "required_variables": ["is_regex", "find_all"],
            "arguments": [
                {"name": "filename", "prompt": "Enter the file's name: ", "type": str}
            ],
        },
        {
            "name": "Gather browser history",
            "function": do_browser_history,
            "arguments": [],
        },
        {
            "name": "Gather command history",
            "function": do_command_history,
            "arguments": [],
        },
    ]

    # Display the menu
    for index, func in enumerate(functions):
        print(f"{index}: {func['name']}")

    # Get user's choice
    index = int(input("Enter the number of the function you'd like to perform: "))
    selected = functions[index]

    for rv in selected.get("required_variables", []):
        current_val = globals().get(rv)
        if isinstance(current_val, bool):
            response = input(f"Enter the value for {rv} (y/n): ").strip().lower()
            globals()[rv] = "y" in response

    # Prompt for arguments
    kwargs = {}
    for argument in selected["arguments"]:
        raw = input(argument["prompt"])
        if argument["type"] == int:
            kwargs[argument["name"]] = int(raw)
        else:
            kwargs[argument["name"]] = raw.strip()

        # Any non-bool required variables?

    # Call the function
    selected["function"](**kwargs)


########
# Main #
########


def main():
    global verbosity
    global environmental_variables
    global case_insensitive
    global is_regex
    global find_all
    global user

    ###################
    # Parse Arguments #
    ###################

    parser = argparse.ArgumentParser(prog=PROGRAM_NAME, description=ABOUT, usage=USAGE)
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

    #################
    # Set Variables #
    #################

    verbosity = args.verbosity
    with suppress(AttributeError):
        case_insensitive = args.insensitive
        is_regex = args.regex
        find_all = args.find_all
        user = args.user

    ############
    ## Config ##
    ############

    if args.function == "config":
        do_config()

    ##########
    ## Info ##
    ##########

    if args.function == "info":
        if args.ip:
            do_ip_info(args.ip)
        elif args.domain:
            do_domain_info(args.domain)
        elif args.url:
            do_url_info(args.url)

    ############
    ## Search ##
    ############

    if args.function == "search":
        if args.filename:
            do_filename_search(args.filename)

    ###########
    ## Tools ##
    ###########
    if args.function == "tools":
        # Test Link: https://urldefense.com/v3/__https:/conferences.stjude.org/g87vv8?i=2NejfAgCkki403xbcRpHuw&locale=en-US__;!!NfcMrC8AwgI!cq3afLDXviFyix2KeJ62VsQBrrZOgfyZu1fks7uQorRGX6VOgcDaUgTpxFdJRmXMdtU5zsmZB9PUw-TmquYgbIGIYUDPsQ$
        if args.url_unwrap:
            do_url_unwrap(args.url_unwrap)

        elif args.browserhistory:
            do_browser_history()

        elif args.csvs:
            do_combine_csvs(args.csvs)

        elif args.cmdhistory:
            do_command_history()

    if not args.function:
        print(ABOUT)
        print(USAGE)
        print(f"You did not provide a function for {PROGRAM_NAME} to do. ")
        if "y" in input("Would you like to Enter interactive mode? (y/n): ").lower():
            interactive_mode()


if __name__ == "__main__":
    main()
