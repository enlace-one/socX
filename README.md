# socx
A collection of helpful tools for a soc analyst. Easily search for IPs, domains, and find files on the system.

## Installing
python -m pip install --index-url https://test.pypi.org/simple/ --no-deps socx
or 
python -m pip install -i https://test.pypi.org/simple/ socx==0.0.3

## Uploading Python Package
python -m build
python -m twine upload --repository testpypi dist/*