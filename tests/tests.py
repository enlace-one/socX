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
    # print(output.stderr, output.stdout)


def test_combine_csvs():
    output = run("combine --csvs 2")
    assert "ValueError: No objects to concatenate" in str(output.stderr)


if __name__ == "__main__":
    tests = [
        test_combine_csvs,
        test_unwrap_url,
        test_find_file,
    ]
    for test in tests:
        print(f"Running {test.__name__}...")
        test()
        print(f"\tTest PASSED!")
