# Certwatcher
This is absolutely experimental and filters the certificate registration stream provided by [CaliDog/certstream-python](https://github.com/calidog/certstream-python). Custom filters can be added using yara rules, see certwatcher/rules directory for that.

## Installation
```
$ git clone https://github.com/3c7/certwatcher
$ cd certwatcher
$ virtualenv . && . bin/activate
$ pip install --editable .
$ # Example call:
$ certwatcher -v -y path/to/yara/rules -d 'de.yar'
```
## Example output
```
[De_domains] matches domain www.google.de.
```