# sigv4
Amazon Web Services Signature Version 4 request signing in Nim

_For AWS APIs in Nim, see https://github.com/disruptek/atoz_

The request signing process is documented at https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html and most of the procedures in this code should be identifiable in that documentation.

Additional documentation for this module may be generated via `nim doc sigv4.nim`, which will author an HTML document `sigv4.html`.

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
  date = "20150830T123600Z"
  
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

## Details
- This code requires nimcrypto https://github.com/cheatfate/nimcrypto (for SHA/HMAC).
- Invoke with `nim c -r sigv4.nim` to run the tests, which (as above) use values from the AWS documentation.
