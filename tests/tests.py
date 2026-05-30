import os
import sys
from pathlib import Path

# Add src directory to Python path
ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"

sys.path.insert(0, str(SRC_DIR))

from typer.testing import CliRunner
from socx import socx

runner = CliRunner()

TEST_FILES_DIR = ROOT_DIR / "tests" / "test_files"

print(f"Using test files in {TEST_FILES_DIR}")

last_result = None

# Command To Test:
# python "src/socx/socx.py"


# ----------------#
# Helper
# ----------------#


def run_cli(args):
    global last_result

    if isinstance(args, str):
        args = args.split()

    last_result = runner.invoke(
        socx.app,
        args,
        catch_exceptions=False,
    )

    return last_result


# ----------------#
# Tests
# ----------------#


def test_unwrap_url():

    wrapped_url = (
        "https://nam01.safelinks.protection.outlook.com/"
        "?url=https%3A%2F%2Fgoogle.com"
    )

    result = socx.unwrap_url(wrapped_url)

    assert "google.com" in result


def test_help():

    result = run_cli(["--help"])

    assert result.exit_code == 0
    assert "SOCX" in result.stdout


def test_default_banner():

    result = run_cli([])

    assert result.exit_code == 0
    assert "Version:" in result.stdout


def test_combine_csvs():

    result = run_cli(
        [
            "combine",
            "--directory",
            str(TEST_FILES_DIR),
        ]
    )

    assert result.exit_code == 0
    assert "\\tests\\test_files\\socx_combined_file" in result.stdout.lower()
    saved_file_path = result.stdout.lower().split("saved")[1].strip()
    expected_content = """name, id,source
bob,1,assets.csv
ted,2,assets2.csv"""
    with open(saved_file_path, "r") as f:
        content = f.read().strip()
        if content != expected_content:
            print(content)
        assert content == expected_content

    os.remove(saved_file_path)


def test_combine_no_csvs():

    empty_dir = TEST_FILES_DIR / "empty"

    empty_dir.mkdir(exist_ok=True)

    result = run_cli(
        [
            "combine",
            "--directory",
            str(empty_dir),
        ]
    )

    assert result.exit_code == 0
    assert "not enough csvs" in result.stdout.lower()


def test_determine_argument_type_ip():
    ip = "8.8.8.8"
    result = socx.determine_info_argument_type(ip)
    if result != "ip":
        print(f"Result was {result}")
    assert result == "ip"


def test_determine_argument_type_domain():
    domain = "google.com"
    result = socx.determine_info_argument_type(domain)
    if result != "domain":
        print(f"Result was {result}")
    assert result == "domain"


def test_determine_argument_type_url():
    url = "https://google.com"
    result = socx.determine_info_argument_type(url)
    if result != "url":
        print(f"Result was {result}")
    assert result == "url"


def test_info_command_ip():
    ip = "8.8.8.8"
    result = run_cli(["info", ip])
    assert "dns.google" in result.stdout
    assert "Pingable: True" in result.stdout
    assert "Organization: Google" in result.stdout


def test_find_command():

    result = run_cli(
        [
            "find",
            "PhineasAndFerb.txt",
            "--directory",
            str(TEST_FILES_DIR),
        ]
    )

    assert result.exit_code == 0
    # try:
    assert "PhineasAndFerb.txt" in result.output
    # except:
    #     print(f"File name not in {result.stdout}. {result.stderr}")
    #     assert "PhineasAndFerb.txt" in result.stdout


def test_find_command_not_found():

    result = run_cli(
        [
            "find",
            "NotARealFile.txt",
            "--directory",
            str(TEST_FILES_DIR),
        ]
    )

    assert result.exit_code == 0
    assert "not found" in result.stdout.lower()


def test_regex_find():

    result = run_cli(
        [
            "find",
            "Phineas.*",
            "--directory",
            str(TEST_FILES_DIR),
            "--regex",
        ]
    )

    assert result.exit_code == 0
    assert "PhineasAndFerb.txt" in result.stdout


# ----------------#
# Easy runner
# ----------------#

if __name__ == "__main__":

    tests = [
        value
        for func, value in locals().items()
        if func.startswith("test") and callable(value)
    ]

    passed = 0
    failed = 0

    print(f"\nRunning {len(tests)} tests...\n")

    for test in tests:

        print(f"Running {test.__name__}...")

        try:

            test()

            print("\tPASSED")

            passed += 1

        except Exception as e:

            failed += 1

            print("\tFAILED")

            if last_result:

                print("EXIT:", last_result.exit_code)
                print("OUTPUT:", repr(last_result.output))
                print("EXCEPTION:", repr(last_result.exception))
                print("STDOUT:", repr(last_result.stdout_bytes))
                print("STDERR:", repr(last_result.stderr_bytes))

                raise (e)

    print("\n========================")
    print(f"PASSED: {passed}")
    print(f"FAILED: {failed}")
    print("========================")
