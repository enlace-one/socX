import os
import subprocess
import pytest

PYTHON_PATH = "python"
SOX_PATH = "./src/socx/socx.py"

last_output = None


def run(cmd):
    global last_output
    last_output = subprocess.run(
        f"{PYTHON_PATH} {SOX_PATH} {cmd}", capture_output=True, timeout=10
    )
    return last_output


def test_find_file():
    output = run("find -f util.py")
    assert output.stderr == b""
    assert "\\util.py" in str(output.stdout)


def test_unwrap_url():
    test_url = "https://urldefense.com/v3/__https:/conferences.stjude.org/g87vv8?i=2NejfAgCkki403xbcRpHuw&locale=en-US__;!!NfcMrC8AwgI!cq3afLDXviFyix2KeJ62VsQBrrZOgfyZu1fks7uQorRGX6VOgcDaUgTpxFdJRmXMdtU5zsmZB9PUw-TmquYgbIGIYUDPsQ$"
    output = run(
        f"unwrap --url '{test_url}' ",
    )
    assert output.stderr == b""
    assert (
        "https://conferences.stjude.org/g87vv8?i=2NejfAgCkki403xbcRpHuw&locale=en-US"
        in str(output.stdout)
    )


def test_domain_info():
    test_domain = "google.com"
    output = run(
        f"info -d '{test_domain}' ",
    )
    assert output.stderr == b""
    assert "Getting information on google.com" in str(output.stdout)


def test_combine_csvs():
    output = run("combine --csvs 2")
    assert "ValueError: No objects to concatenate" in str(output.stderr)


if __name__ == "__main__":
    tests = [test_combine_csvs, test_unwrap_url, test_find_file, test_domain_info]
    for test in tests:
        print(f"Running {test.__name__}...")
        try:
            test()
            print(f"\tTest PASSED!")
        except Exception as e:
            print(f"stdout: {last_output.stdout}")
            print(f"stderr: {last_output.stderr}")
            raise (e)
