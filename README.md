# SOCX

A collection of helpful tools for a SOC analyst. Easily search for IPs, domains, and find files on the system.

## Installing

python -m pip install socx

### Installing from QA

python -m pip install --index-url https://test.pypi.org/simple/ socx

## Usage

A tool to assist with day to day activites in a security operations center (pronounced "socks")      

Usage:

    socx [universal options] [function] [arguments]

    python socx.py [universal options] [function] [arguments]
        
Examples:

    socx --help

    socx info --help

    socx info 102.02.02.02

    socx -v 3 info google.com

    socx find filename.txt -i False

    socx find fold.*name -r

    socx unwrap "https://urldefense.com/v3/__https:/..."

    socx combine --count 5

    socx awake --minutes 90

    socx awake --restart

## Dev Info

### Uploading Python Package

python -m build

python -m twine upload --repository testpypi dist/*

python -m twine upload dist/*

