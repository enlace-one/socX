import os
import subprocess
import pytest

PYTHON_PATH = "python"
SOX_PATH = "./src/socx/socx.py"


def run(cmd):
    return subprocess.run(
        f"{PYTHON_PATH} {SOX_PATH} {cmd}", capture_output=True, timeout=10
    )


def test_find_file():
    output = run("search -f util.py")
    assert output.stderr == b""
    assert "\\util.py" in str(output.stdout)


def test_unwrap_url():
    test_url = "https://urldefense.com/v3/__https:/conferences.stjude.org/g87vv8?i=2NejfAgCkki403xbcRpHuw&locale=en-US__;!!NfcMrC8AwgI!cq3afLDXviFyix2KeJ62VsQBrrZOgfyZu1fks7uQorRGX6VOgcDaUgTpxFdJRmXMdtU5zsmZB9PUw-TmquYgbIGIYUDPsQ$"
    output = run(
        f"tools --unwrap_url '{test_url}' ",
    )
    print(output.stderr, output.stdout)


test_unwrap_url()
