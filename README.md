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

    socx combine 5

    socx awake 90
    
    socx awake --restart

## Dev Info

## Package Install 

Create venv
```
uv venv
```

Install dev packages:
```
uv pip install -e ".[dev]"
```

Install other packages:
```
uv sync
```

Lock the versions:
```
uv lock
```

Compatability:
```
uv export --format requirements-txt > requirements.txt
```

### Uploading Python Package
```
uv build
```

Test locally in a seperate window without venv
```
uv pip install dist/*.whl
```

Delete old version from dist/*

```
python -m twine upload --repository testpypi dist/*
```

```
python -m twine upload dist/*
```

