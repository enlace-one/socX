try:
    import re
    import string
    from base64 import urlsafe_b64decode
    from urllib.parse import unquote
    from html import unescape
    import json
    import os
    import requests
    import urllib3
    from contextlib import suppress
except ImportError as e:
    print(
        f"""You are missing a required module ({e.name})
Try installing it with:
    pip install {e.name}
or
    python -m pip install {e.name} --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org"""
    )
    exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class URLDefenseDecoder(object):
    __author__ = "Eric Van Cleve"
    __copyright__ = "Copyright 2019, Proofpoint Inc"
    __license__ = "GPL v.3"
    __version__ = "3.0.1"
    __email__ = "evancleve@proofpoint.com"
    __status__ = "Production"

    @staticmethod
    def __init__():
        URLDefenseDecoder.ud_pattern = re.compile(
            r"https://urldefense(?:\.proofpoint)?\.com/(v[0-9])/"
        )
        URLDefenseDecoder.v1_pattern = re.compile(r"u=(?P<url>.+?)&k=")
        URLDefenseDecoder.v2_pattern = re.compile(r"u=(?P<url>.+?)&[dc]=")
        URLDefenseDecoder.v3_pattern = re.compile(
            r"v3/__(?P<url>.+?)__;(?P<enc_bytes>.*?)!"
        )
        URLDefenseDecoder.v3_token_pattern = re.compile(r"\*(\*.)?")
        URLDefenseDecoder.v3_single_slash = re.compile(
            r"^([a-z0-9+.-]+:/)([^/].+)", re.IGNORECASE
        )
        URLDefenseDecoder.v3_run_mapping = {}
        run_values = (
            string.ascii_uppercase + string.ascii_lowercase + string.digits + "-" + "_"
        )
        run_length = 2
        for value in run_values:
            URLDefenseDecoder.v3_run_mapping[value] = run_length
            run_length += 1

    def decode(self, rewritten_url):
        match = self.ud_pattern.search(rewritten_url)
        if match:
            if match.group(1) == "v1":
                return self.decode_v1(rewritten_url)
            elif match.group(1) == "v2":
                return self.decode_v2(rewritten_url)
            elif match.group(1) == "v3":
                return self.decode_v3(rewritten_url)
            else:
                raise ValueError("Unrecognized version in: ", rewritten_url)
        else:
            return rewritten_url  # Edited by me

    def decode_v1(self, rewritten_url):
        match = self.v1_pattern.search(rewritten_url)
        if match:
            url_encoded_url = match.group("url")
            html_encoded_url = unquote(url_encoded_url)
            url = unescape(html_encoded_url)
            return url
        else:
            raise ValueError("Error parsing URL")

    def decode_v2(self, rewritten_url):
        match = self.v2_pattern.search(rewritten_url)
        if match:
            special_encoded_url = match.group("url")
            trans = str.maketrans("-_", "%/")
            url_encoded_url = special_encoded_url.translate(trans)
            html_encoded_url = unquote(url_encoded_url)
            url = unescape(html_encoded_url)
            return url
        else:
            raise ValueError("Error parsing URL")

    def decode_v3(self, rewritten_url):
        def replace_token(token):
            if token == "*":
                character = self.dec_bytes[self.current_marker]
                self.current_marker += 1
                return character
            if token.startswith("**"):
                run_length = self.v3_run_mapping[token[-1]]
                run = self.dec_bytes[
                    self.current_marker : self.current_marker + run_length
                ]
                self.current_marker += run_length
                return run

        def substitute_tokens(text, start_pos=0):
            match = self.v3_token_pattern.search(text, start_pos)
            if match:
                start = text[start_pos : match.start()]
                built_string = start
                token = text[match.start() : match.end()]
                built_string += replace_token(token)
                built_string += substitute_tokens(text, match.end())
                return built_string
            else:
                return text[start_pos : len(text)]

        match = self.v3_pattern.search(rewritten_url)
        if match:
            url = match.group("url")
            singleSlash = self.v3_single_slash.findall(url)
            if singleSlash and len(singleSlash[0]) == 2:
                url = singleSlash[0][0] + "/" + singleSlash[0][1]
            encoded_url = unquote(url)
            enc_bytes = match.group("enc_bytes")
            enc_bytes += "=="
            self.dec_bytes = (urlsafe_b64decode(enc_bytes)).decode("utf-8")
            self.current_marker = 0
            return substitute_tokens(encoded_url)

        else:
            raise ValueError("Error parsing URL")


class InsightVMAPI:
    headers = {
        "User-Agent": "Thunder Client (https://www.thunderclient.com)",
        "Content-Type": "application/json",
        "Accept": "application/json;charset=UTF-8",
    }
    verify = True
    try_unverified_if_failed = True
    asset_search_url = "/api/3/assets/search?page=0&size=5"
    asset_name_search_type = "is"  # is or starts-with usually

    def __init__(self, base_url, api_key):
        self.API_KEY = api_key
        self.BASE_URL = base_url
        self.headers["Authorization"] = f"Basic {self.API_KEY}"

    def request(
        self, method, url_addition, data=None, headers=None, verify=None, timeout=10
    ):
        if headers is None:
            headers = self.headers
        if verify is None:
            verify = self.verify
        try:
            response = requests.request(
                method,
                self.BASE_URL + url_addition,
                data=data,
                headers=self.headers,
                verify=False,
                timeout=10,
            )
        except requests.exceptions.SSLError as e:
            if self.try_unverified_if_failed:
                response = requests.request(
                    method,
                    self.BASE_URL + url_addition,
                    data=data,
                    headers=self.headers,
                    verify=False,
                    timeout=10,
                )
            else:
                raise e
        return response

    def _format_return_string(self, result):
        returnstring = ""
        with suppress(KeyError):
            returnstring += f'Hostname: {result["resources"][0]["hostName"]}\n'
            returnstring += f'R7 ID: {result["resources"][0]["id"]}\n'
            returnstring += f'Desc: {result["resources"][0]["description"]}\n'
            for address in result["resources"][0]["addresses"]:
                returnstring += f'IP: {address["ip"]}, MAC: {address["mac"]}\n'
            returnstring += (
                f'Last Scan: {result["resources"][0]["history"][-1]["date"]}\n'
            )
            returnstring += f'Vulnerabilities: {result["resources"][0]["vulnerabilities"]["total"]}\n'
            returnstring += f'Risk: {result["resources"][0]["riskScore"]}\n'
        return returnstring

    def hostname_search(self, asset_name, ids_only=False):
        """Return the asset IDs found using asset_name"""
        payload = {
            "filters": [
                {
                    "field": "host-name",
                    "lower": "",
                    "operator": self.asset_name_search_type,
                    "upper": "",
                    "value": asset_name,
                }
            ],
            "match": "all",
        }
        return self._asset_search(payload, ids_only=ids_only)

    def ip_search(self, ip, ids_only=False):
        """Return the asset IDs found using asset_name"""
        payload = {
            "filters": [
                {
                    "field": "ip-address",
                    "lower": "",
                    "operator": "is",
                    "upper": "",
                    "value": ip,
                }
            ],
            "match": "all",
        }
        return self._asset_search(payload, ids_only=ids_only)

    def _asset_search(self, payload, ids_only=False):
        """Return the assets found using asset_name"""
        response = self.request("POST", self.asset_search_url, json.dumps(payload))
        if ids_only:
            return [asset["id"] for asset in response.json()["resources"]]
        else:
            return response.json()["resources"]

    def _delete_asset(self, asset_id):
        """Delete the asset with the given id"""
        response = self.request("DELETE", f"/api/3/assets/{asset_id}")
        return response.status_code

    def cve_search(self, cve, ids_only=False):
        """Return the asset IDs found using cve"""
        payload = {
            "filters": [
                {
                    "field": "cve",
                    "lower": "",
                    "operator": "is",
                    "upper": "",
                    "value": cve,
                }
            ],
            "match": "all",
        }
        return self._asset_search(payload, ids_only=ids_only)
