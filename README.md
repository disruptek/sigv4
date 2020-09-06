# sigv4
Amazon Web Services Signature Version 4 request signing in Nim

[![Test Matrix](https://github.com/disruptek/sigv4/workflows/CI/badge.svg)](https://github.com/disruptek/sigv4/actions?query=workflow%3ACI)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/disruptek/sigv4?style=flat)](https://github.com/disruptek/sigv4/releases/latest)
![Minimum supported Nim version](https://img.shields.io/badge/nim-1.0.8%2B-informational?style=flat&logo=nim)
[![License](https://img.shields.io/github/license/disruptek/sigv4?style=flat)](#license)
[![buy me a coffee](https://img.shields.io/badge/donate-buy%20me%20a%20coffee-orange.svg)](https://www.buymeacoffee.com/disruptek)

_For AWS APIs in Nim, see https://github.com/disruptek/atoz_

The request signing process is documented at
https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html and most
of the procedures in this code should be identifiable in that documentation.

## Installation

By default, we use https://github.com/jangko/nimSHA2 for SHA256/SHA512
routines.

If you already have a dependency on NimCrypto, you can use that instead by
passing `--define:sigv4UseNimCrypto` to the compiler.

```
$ nimph clone disruptek/jason
```
or if you think package managers are stupid,
```
$ git clone https://github.com/disruptek/sigv4
$ echo '--path="$config/sigv4/"' >> nim.cfg
```
or if you're still using Nimble like it's 2012,
```
$ nimble install https://github.com/disruptek/sigv4
```

## Usage
```nim
import json
import httpcore

import sigv4

let
  # the URL of the request
  url = "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08"

  # an AWS Secret Key
  secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

  # the body of the request; eg. POST content
  payload = ""

  # the AWS region against which you are querying
  region = "us-east-1"

  # the short name of the service as you might find in, say, an ARN
  service = "iam"

  # an enum representing the signing algorithm, eg. SHA256 or SHA512
  digest = SHA256

  # an ISO8601 date string attached to the request
  date = makeDateTime()

  # a JsonNode holding the query string key/value pairs, as provided by the stdlib
  query = %* {
    "Action": "ListUsers",
    "Version": "2010-05-08",
  }

  # http headers as provided by the stdlib
  headers = newHttpHeaders(@[
    ("Host", "iam.amazonaws.com"),
    ("Content-Type", "application/x-www-form-urlencoded; charset=utf-8"),
    ("X-Amz-Date", date),
  ])

  # compose a credential scope
  scope = credentialScope(region=region, service=service, date=date)

  # compose the canonical request
  request = canonicalRequest(HttpGet, url, query, headers, payload, digest=digest)

  # use the request and scope to compose a string-to-sign
  sts = stringToSign(request.hash(digest), scope, date=date, digest=digest)

  # calculate the signature for the request using a secret key
  signature = calculateSignature(secret=secret, date=date, region=region,
                                 service=service, tosign=sts, digest=digest)
assert signature == "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
```

## Documentation
See [the documentation for the sigv4 module](https://disruptek.github.io/sigv4/sigv4.html) as generated directly from the source.

## Tests
The tests use example values from the AWS documentation as above.
```
$ nimble test
```

## License
MIT
