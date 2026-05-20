#!/usr/bin/env python3

import ipaddress
import os
import re
import sys
import zipfile
import socket
import subprocess
from urllib.parse import unquote, urlparse
import datetime as dt
import sqlite3 as sql

try:
    from . import util
except:
    import util

import requests
import pandas as pd
import typer
import keyring
import xml.etree.ElementTree as ET
from pathlib import Path

PROGRAM_NAME = "socx"
# Also change this in pyproject.toml
VERSION = "2.5.0"
ABOUT = rf"""
   _____ ____  _______  __
  / ___// __ \/ ____/ |/ /
  \__ \/ / / / /    |   / 
 ___/ / /_/ / /___ /   |  
/____/\____/\____//_/|_|  

Version: {VERSION}
A tool to assist with day to day activites in a security operations center (pronounced "socks")

Visit https://enlace.one/ for more information.
"""
USAGE = rf"""Usage:
    {PROGRAM_NAME} [universal options] [function] [arguments]
    python {PROGRAM_NAME}.py [universal options] [function] [arguments]
        
Examples:
    {PROGRAM_NAME} --help
    {PROGRAM_NAME} info --help
    {PROGRAM_NAME} info 103.03.03.03
    {PROGRAM_NAME} -v 3 info google.com
    {PROGRAM_NAME} find filename.txt -i False
    {PROGRAM_NAME} find fold.*name -r
    {PROGRAM_NAME} unwrap "https://urldefense.com/v3/__https:/..."
    {PROGRAM_NAME} combine --count 5
    {PROGRAM_NAME} awake --minutes 90
    {PROGRAM_NAME} awake --restart
"""

app = typer.Typer(help="SOCX - Security Operations Center utility toolkit")

# ----------------#
# Globals
# ----------------#

ENV_DEFAULTS = {"DefaultVerbosity": "2", "VirusTotalAPIKey": ""}


class AppState:
    def __init__(self):
        self.verbosity = 1


state = AppState()


def p(*args, v=1):
    if state.verbosity >= v:
        typer.echo(" ".join(str(a) for a in args))


def get_env(name: str):
    val = keyring.get_password("system", "_socX__" + name)
    return val if val is not None else ENV_DEFAULTS.get(name, "")


default_verbosity = int(get_env("DefaultVerbosity"))

# ----------------#
# Banner
# ----------------#


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    verbosity: int = typer.Option(default_verbosity, "--verbosity", "-v"),
):
    state.verbosity = verbosity

    if ctx.invoked_subcommand is None:
        print(ABOUT)
        print(USAGE)
        raise typer.Exit()


# ----------------#
# URL utilities
# ----------------#


def unwrap_url(url: str) -> str:
    decoder = util.URLDefenseDecoder()

    if "safelinks" in url:
        p("Safelink detected, removing...", v=4)
        parts = [t for t in re.split(r"&|\?", url) if t.startswith("url=")]
        if parts:
            url = parts[0].split("=", 1)[1]
            url = unquote(url)
        p(f"URL after removing Safelinks: \n{url}\n", v=5)

    url = decoder.decode(url)

    p(f"URL after removing Proofpoint URL wrapping: \n{url}\n", v=5)

    return decoder.decode(url)


# ----------------#
# Info tools
# ----------------#


def print_ip_info(ip: str):
    p("Retrieving WHOIS information", v=5)

    try:
        url = f"https://whois.arin.net/rest/ip/{ip}"
        ip_xml = requests.get(url, timeout=10).text

        ns = {"ns": "https://www.arin.net/whoisrws/core/v1"}
        root = ET.fromstring(ip_xml)

        org_url = root.find("ns:orgRef", ns).text
        org_xml = requests.get(org_url, timeout=10).text
        org = ET.fromstring(org_xml)

        p(f"Organization: {org.find('ns:name', ns).text}")
        p(f"City: {org.find('ns:city', ns).text}")
        p(f"Country: {org.find('ns:iso3166-1/ns:name', ns).text}")
        p(f"Handle: {org.find('ns:handle', ns).text}")
        p(f"Registered: {org.find('ns:registrationDate', ns).text}")

    except Exception as e:
        p(f"WHOIS error: {e}")


def ping(ip):
    p("Running ping test", v=5)
    result = subprocess.run(["ping", "-n", "1", ip], capture_output=True, text=True)
    if result.returncode != 0:
        p(f"Pingable: False ({ip} is down)")
    elif "Reply" in result.stdout:
        matches = re.search(r"Minimum = (\d+ms)", result.stdout)
        if matches:
            speed = matches.group(1)
            p(f"Pingable: True ({ip} is up). Round trip speed: {speed}")
        else:
            p("Cannot determine ping speed", v=5)
            p(f"Pingable: True ({ip} is up)")
    else:
        p("Cannot automatically detect ping success. See stdout below.", v=4)
        p(f"{result.stdout}")


def determine_info_argument_type(argument: str) -> str:
    """
    Determines if the input is an IP, domain, or URL.
    Returns: "ip", "domain", or "url"
    """

    argument = argument.strip()

    # 1. URL check (must come first)
    parsed = urlparse(argument)
    if parsed.scheme and parsed.netloc:
        return "url"

    # Sometimes URLs come without scheme
    if argument.startswith(("http://", "https://", "ftp://")):
        return "url"

    # 2. IP check
    try:
        ipaddress.ip_address(argument)
        return "ip"
    except ValueError:
        pass

    # 3. Domain check (basic validation)
    domain_regex = re.compile(r"^(?=.{1,253}$)" r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

    if domain_regex.match(argument):
        return "domain"

    return "unknown"


@app.command()
def info(argument: str = typer.Argument(None, help="An IP, Domain, or URL")):
    """Get info on IP, domain, or URL"""

    p("Starting info lookup", v=3)

    argument_type = determine_info_argument_type(argument)
    ip = domain = url = argument  # Used later

    if argument_type == "unknown":
        p("Error: Could not determine argument type.")
        return
    p(f"Determined argument is of type {argument_type}.", v=5)

    if argument_type == "ip":

        p(f"IP lookup requested for {ip}", v=3)

        try:
            p("Resolving hostname", v=5)

            host = socket.gethostbyaddr(ip)

            p(f"Hostname: {host[0]}")

        except Exception as e:
            p(f"Hostname lookup failed", v=2)
            p(f"{e}", v=4)

        ping(ip)

        print_ip_info(ip)

    elif argument_type == "domain":

        p(f"Domain lookup requested for {domain}", v=3)

        if domain.startswith("http"):
            p("Stripping URL scheme", v=4)
            domain = domain.split("//")[1]

        domain = domain.replace("www.", "")

        p(f"Normalized domain: {domain}", v=3)

        try:

            p("Resolving domain", v=5)

            ip_resolved = socket.gethostbyname(domain)

            p(f"IP: {ip_resolved}")

        except Exception as e:

            p(f"Domain resolution failed: {e}", v=1)

            ip_resolved = None

        ping(domain)

        if ip_resolved:

            print_ip_info(ip_resolved)

        p(f"WHOIS: https://www.whois.com/whois/{domain}")

    elif argument_type == "url":

        p("URL lookup requested", v=3)

        p("Unwrapping URL", v=4)

        url = unwrap_url(url)

        p(f"Unwrapped: {url}", v=2)

        api = get_env("VirusTotalAPIKey")

        if api:

            p("VirusTotal API key detected", v=3)

            p("Submitting URL to VirusTotal...", v=2)

            try:

                resp = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers={"x-apikey": api},
                    data={"url": url},
                    timeout=10,
                )

                p(f"VirusTotal submission status: {resp.status_code}")

                p(resp.text, v=5)

            except Exception as e:

                p(f"VirusTotal submission failed: {e}", v=1)
                p(e, v=5)

        else:
            p("VirusTotal API key not configured", v=3)


# ----------------#
# File search
# ----------------#
class FileFinder:
    def __init__(
        self, filename, directory, regex, find_all, case_sensitive, smart_search
    ):
        self.filename = filename
        self.directory = directory
        self.regex = regex
        self.find_all = find_all
        self.case_sensitive = case_sensitive
        self.smart_search = smart_search
        self.results = []
        self.directories_searched = []
        self.done = False

    def matches(self, item_to_match):
        if self.regex and self.case_sensitive:
            return bool(re.search(self.filename, item_to_match))
        elif self.regex:
            return bool(re.search(self.filename, item_to_match, re.IGNORECASE))
        elif self.case_sensitive:
            return self.filename in item_to_match
        else:
            return self.filename.lower() in item_to_match.lower()

    def search(self):
        current_directory = self.directory

        # Search current directory tree
        self.search_directory(current_directory)

        if not self.done and self.smart_search:
            p(
                f"Not found in '{self.directory}' \nStarting broader smart search...",
                v=3,
            )

        # Walk upward through parent directories
        while not self.done and self.smart_search:
            parent = os.path.dirname(os.path.abspath(current_directory))

            # Avoid infinite loop at filesystem root
            if parent == os.path.abspath(current_directory):
                break

            self.search_directory(parent)
            current_directory = parent

        # Search other drives
        while not self.done:
            current_drive = os.path.splitdrive(os.path.abspath(self.directory))[
                0
            ].upper()

            p(f"Done searching current drive ({current_drive})", v=2)

            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                drive = f"{letter}:"

                # Skip current drive
                if drive == current_drive:
                    continue

                # Skip nonexistent drives
                if not os.path.exists(f"{drive}\\"):
                    continue

                p(f"Searching drive {drive}...", v=2)

                self.search_directory(f"{drive}\\")

                if self.done:
                    break

            break

    def search_directory(self, directory):
        for root, dirs, files in os.walk(directory):
            if os.path.abspath(root) in self.directories_searched:
                dirs.clear()  # Prunes os.walk from descending into subdirectories
                continue
            p(f"Checking '{os.path.abspath(root)}'", v=5)
            for f in files:
                if self.matches(f):
                    m = os.path.join(root, f)
                    p(f"Match found: {m}", v=2)
                    self.results.append(m)
                    if not self.find_all:
                        self.done = True
                        break
        self.directories_searched.append(os.path.abspath(directory))

    def report(self):
        if self.results:
            p(f"Result{'s' if len(self.results) > 1 else ''}:")
            for r in self.results:
                p(f"- {r}")
        else:
            p(
                f"Not found {'anywhere' if self.smart_search else 'in ' + self.directory}"
            )


@app.command()
def find(
    filename,
    directory: str = typer.Option(".", "-d", "--directory"),
    regex: bool = typer.Option(False, "-r", "--regex"),
    find_all: bool = typer.Option(False, "-a", "--all"),
    case_sensitive: bool = typer.Option(False, "-c", "--case-sensitive"),
    skip_smart_search: bool = typer.Option(False, "-s", "--skip_smart"),
):
    """Search for a file or folder"""

    if find_all and not skip_smart_search:
        p("Smart search not available as find_all is True", v=2)
        skip_smart_search = True

    drive_root = os.path.splitdrive(os.path.abspath(directory))[0] + os.sep
    if find_all and os.path.abspath(directory) != drive_root:
        p(f"Starting search from drive root ({drive_root}) as find_all is True", v=2)
        directory = drive_root

    if not skip_smart_search:
        p(
            "Using smart search (starts in current working directory and works backwards)",
            v=4,
        )

    p(f"Case sensitive search: {case_sensitive}", v=5)
    p(f"Regex search: {regex}", v=5)

    finder = FileFinder(
        filename,
        directory,
        regex,
        find_all,
        case_sensitive,
        smart_search=not skip_smart_search,
    )
    finder.search()
    finder.report()


# ----------------#
# URL unwrap
# ----------------#


@app.command()
def unwrap(url: str):
    """Unwrap a safelinks URL"""
    url = unwrap_url(url)
    p("Unwrapped URL:", v=2)
    p(url)


# ----------------#
# CSV combine
# ----------------#


@app.command()
def combine(
    directory: str = typer.Option(".", "-d", "--directory"),
    count: str = typer.Option(2, "-c", "--count"),
):
    """Combine multiple CSVs of the same format"""

    p("Starting combine CSV", v=2)

    count = int(count)

    directory = os.path.abspath(directory)

    p(f"Using directory: {directory}", v=3)
    p(f"Looking for {count} CSV file(s)", v=3)

    files = sorted(Path(directory).glob("*.csv"), key=os.path.getmtime, reverse=True)

    p(f"Found {len(files)} CSV file(s)", v=3)

    if len(files) < count:
        p("Not enough CSVs")
        raise typer.Exit()

    dfs = []

    for f in files[:count]:
        p(f"Loading {f.name}", v=4)

        df = pd.read_csv(f)

        p(f"Loaded {len(df)} row(s)", v=5)

        df["source"] = f.name
        dfs.append(df)

    p("Concatenating dataframes", v=3)

    cleaned = [
        df
        for df in dfs
        if df is not None and not df.empty and not df.isna().all().all()
    ]

    if cleaned:
        out = pd.concat(dfs)
    else:
        pd.DataFrame()

    out = pd.concat(dfs)

    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")

    output_filename = f"SOCX_COMBINED_FILE_{timestamp}.csv"

    p(f"Writing output to {output_filename}", v=4)

    output_filename = os.path.join(directory, output_filename)

    out.to_csv(output_filename, index=False)

    p(f"Saved {output_filename}", v=1)


# ----------------#
# ZIP extract
# ----------------#


@app.command()
def unzip(directory: str = ".", count: int = 1):
    """Unzip multiple zip files at once"""

    p("Starting ZIP extraction", v=2)

    if directory == ".":
        p("Using current working directory", v=3)

    directory = os.path.abspath(directory)

    p(f"Using directory: {directory}", v=2)
    p(f"Looking for {count} ZIP file(s)", v=2)

    zips = sorted(
        Path(directory).glob("*.zip"),
        key=os.path.getmtime,
        reverse=True,
    )

    p(f"Found {len(zips)} ZIP file(s)", v=3)

    if len(zips) < count:
        p("Not enough ZIP files found", v=1)
        raise typer.Exit()

    for z in zips[:count]:

        p(f"Extracting {z.name}", v=2)

        try:
            with zipfile.ZipFile(z, "r") as zip_ref:

                p(f"Extracting into {directory}", v=4)

                zip_ref.extractall(directory)

                p(
                    f"Extracted {len(zip_ref.namelist())} file(s)",
                    v=3,
                )

            p(f"Successfully extracted {z.name}", v=1)

        except Exception as e:
            p(f"Error extracting {z.name}: {e}", v=1)
            p(e, v=5)


# ----------------#
# Keep awake
# ----------------#


@app.command()
def awake(minutes: int = 60):
    """Keep your screen awake"""
    interval = 10
    iterations = int((minutes * 60) / interval)

    p(f"Keeping awake for {minutes} minutes")

    cmd = [
        "powershell",
        "-Command",
        f"$w=new-object -com wscript.shell;for($i=0;$i -lt {iterations};$i++){{"
        f"$w.SendKeys('%');start-sleep {interval}}}",
    ]

    subprocess.run(cmd)


# ----------------#
# Browser history
# ----------------#


@app.command()
def browser_history(user: str = "~"):
    """Get browser history artifacts"""
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
                        if f"{e}" == "database is locked":
                            p("\tClose the browser and try again", v=3)


# ----------------#
# Command history
# ----------------#


@app.command()
def cmd_history(user: str = "~"):
    """Get command history path"""
    path = os.path.expanduser(
        user
        + "/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
    )

    if os.path.exists(path):
        out = Path("powershell_history.txt")
        out.write_text(Path(path).read_text())
        p("Saved powershell_history.txt")


# ----------------#
# Configure pip
# ----------------#


@app.command()
def configure_pip():
    """Configure pip for user and active virtual environment"""

    uploaded_prior_to = "P14D"

    scopes = {
        "site": [
            sys.executable,
            "-m",
            "pip",
            "config",
            "--site",
            "set",
        ],
        "user": [
            sys.executable,
            "-m",
            "pip",
            "config",
            "--user",
            "set",
        ],
    }

    for scope_name, base in scopes.items():

        subprocess.run(
            base
            + [
                "global.trusted-host",
                "pypi.org",
            ],
            check=True,
        )

        subprocess.run(
            base
            + [
                "global.trusted-host",
                "files.pythonhosted.org",
            ],
            check=True,
        )

        subprocess.run(
            base
            + [
                "global.trusted-host",
                "pypi.python.org",
            ],
            check=True,
        )

        subprocess.run(
            base
            + [
                "global.uploaded-prior-to",
                uploaded_prior_to,
            ],
            check=True,
        )

        typer.echo(f"Configured pip {scope_name} scope")

    typer.echo(f"uploaded-prior-to = {uploaded_prior_to}")


# ----------------#
# Config
# ----------------#


@app.command()
def config():
    """List and set SOCX configuration variables"""
    keys = list(ENV_DEFAULTS.keys())

    p("Configuration Keys:")

    for i, k in enumerate(keys):
        p(f"{i}: {k}")

    idx = int(typer.prompt("Select key index to view and change one"))
    key = keys[idx]

    old = get_env(key)
    p(f"Current: {old}")

    new = typer.prompt("New value")

    keyring.set_password("system", "_socX__" + key, new)
    p("Updated")


# ----------------#
# Entry
# ----------------#

if __name__ == "__main__":
    app()
