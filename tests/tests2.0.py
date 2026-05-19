import sys
from pathlib import Path

# Add src directory to Python path
ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"

sys.path.insert(0, str(SRC_DIR))

from typer.testing import CliRunner
from socx.socx2 import app, find, unwrap_url

runner = CliRunner()

TEST_FILES_DIR = ROOT_DIR / "tests" / "test_files"

print(f"Using test files in {TEST_FILES_DIR}")

last_result = None


# ----------------#
# Helper
# ----------------#


def run_cli(args):
    global last_result

    if isinstance(args, str):
        args = args.split()

    last_result = runner.invoke(
        app,
        args,
        catch_exceptions=False,
    )

    return last_result


# ----------------#
# Tests
# ----------------#


def test_find_command():

    result = run_cli(
        [
            "find",
            "PhineasAndFerb.txt",
            "--directory",
            str(TEST_FILES_DIR),
        ]
    )

    print(f"Result output: {result.output}")

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
            "--filename",
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
            "--filename",
            "Phineas.*",
            "--directory",
            str(TEST_FILES_DIR),
            "--regex",
        ]
    )

    assert result.exit_code == 0
    assert "PhineasAndFerb.txt" in result.stdout


def test_unwrap_url():

    wrapped_url = (
        "https://nam01.safelinks.protection.outlook.com/"
        "?url=https%3A%2F%2Fgoogle.com"
    )

    result = unwrap_url(wrapped_url)

    assert "google.com" in result


def test_help():

    result = run_cli(["--help"])

    assert result.exit_code == 0
    assert "SOCX" in result.stdout


def test_default_banner():

    result = run_cli([])

    assert result.exit_code == 0
    assert "Version:" in result.stdout


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
