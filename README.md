# Certwatcher
This is absolutely experimental and filters the certificate registration stream provided by [CaliDog/certstream-python](https://github.com/calidog/certstream-python). Custom filters can be added using the given json scheme:
```json
{
  "id": "https://github.com/3c7/certwatcher/",
  "$schema": "http://json-schema.org/draft-06/schema#",
  "title": "Rule",
  "description": "A single rule, that can be used in a ruleset",
  "type": "object",
  "properties": {
    "name": {
      "type": "string",
      "description": "Name for that rule"
    },
    "searchString": {
      "description": "String to search for",
      "type": "string"
    },
    "count": {
      "description": "The count of the given string to search for",
      "type": "integer",
      "minimum": 1,
      "default": 1
    },
    "searchIn": {
      "description": "Where to search for that string",
      "type": "string",
      "enum": ["domain", "certificateAuthority"]
    },
    "description": {
      "type": "string",
      "description": "Description for that rule"
    },
    "color": {
      "type": "string",
      "enum": ["red", "yellow", "green"]
    }
  }
}
```
At the moment, that schema is very limiting, but I'm currently working on extending that to allow rule chaining and boolean operations.

## Installation
```
$ git clone https://github.com/3c7/certwatcher
$ cd certwatcher
$ virtualenv . && . bin/activate
$ pip install .
$ # Example call:
$ certwatcher -v -r certwatcher/rules -s certwatcher/schemas -d 'de-domain'
```
## Example output
```
[Rule: Subdomain] matches www.secure-apple.com-itunes-secureinfoaccountlogin.com.
```