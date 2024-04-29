# socx
A collection of helpful tools for a soc analyst. Easily search for IPs, domains, and find files on the system.

## Installing
python -m pip install socx

## Usage
socx info -ip 1.2.3.4
socx -v 3 info -d google.com
socx search -f filename.txt -i
socx search -f fold.*name -r
socx tools --url_unwrap "https://urldefense.com/v3/__https:/...

## Other Information

### Install Testing Version
python -m pip install --index-url https://test.pypi.org/simple/ --no-deps socx
or 
python -m pip install -i https://test.pypi.org/simple/ socx==0.0.3

### Uploading Python Package
python -m build
python -m twine upload dist/*
python -m twine upload --repository testpypi dist/*