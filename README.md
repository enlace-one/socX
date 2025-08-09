# SOCX
A collection of helpful tools for a SOC analyst. Easily search for IPs, domains, and find files on the system.

## Installing
python -m pip install socx

### Installing from QA
python -m pip install --index-url https://test.pypi.org/simple/ socx

## Usage
A tool to assist with day to day activites in a security operations center (pronounced "socks")      

Usage:
    
    socx [universal options] 
    \[function] \[arguments]

or

    python socx.py [universal options] [function] [arguments]

Examples:

    socx --help

    socx info -h
    
    socx info -ip 1.2.3.4
    
    socx -v 3 info -d google.com
    
    socx find -f filename.txt -i
    
    socx find -f fold.*name -r
    
    socx unwrap --url "https://urldefense.com/v3/__https:/..."
    
    socx combine --csvs 5
    
    socx awake --minutes 90
    
    socx awake --restart

## Other Information

### Install Testing Version
python -m pip install --index-url https://test.pypi.org/simple/ --no-deps socx

or 

python -m pip install -i https://test.pypi.org/simple/ socx==0.0.3

## Dev Info

### Uploading Python Package
python -m build

python -m twine upload --repository testpypi dist/*

python -m twine upload dist/*

