import std/json

import testes

# use an include whatfer testing encodedSegment, etc.
include sigv4

when defined(sigv4UseNimCrypto):
  checkpoint "testing with nimcrypto"
else:
  checkpoint "testing with nimSHA2"

testes:
  let
    url = "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08"
    secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    region = "us-east-1"
    service = "iam"
    digest = SHA256
    normal = Default
    date = "20150830T123600Z"
    q = %* {
      "Action": "ListUsers",
      "Version": "2010-05-08",
    }
    heads = @[
      ("Host", "iam.amazonaws.com"),
      ("Content-Type", "application/x-www-form-urlencoded; charset=utf-8"),
      ("X-Amz-Date", date),
    ]

  test "encoded segment":
    check "".encodedSegment(passes=1) == ""
    check "foo".encodedSegment(passes=1) == "foo"
    check "foo".encodedSegment(passes=2) == "foo"
    check "foo bar".encodedSegment(passes=1) == "foo%20bar"
    check "foo bar".encodedSegment(passes=2) == "foo%2520bar"

  test "encoded components":
    check "/".encodedComponents(passes=1) == "/"
    check "//".encodedComponents(passes=1) == "//"
    check "foo".encodedComponents(passes=1) == "foo"
    check "/foo/bar".encodedComponents(passes=1) == "/foo/bar"
    check "/foo/bar/".encodedComponents(passes=1) == "/foo/bar/"
    check "/foo bar".encodedComponents(passes=1) == "/foo%20bar"
    check "/foo bar/".encodedComponents(passes=2) == "/foo%2520bar/"
    check "foo bar".encodedComponents(passes=2) == "foo%2520bar"
    check "foo bar/bif".encodedComponents(passes=2) == "foo%2520bar/bif"

  test "encoded path":
    check "/".encodedPath(Default) == "/"
    check "/".encodedPath(S3) == "/"
    check "//".encodedPath(Default) == "/"
    check "//".encodedPath(S3) == "//"
    check "foo bar".encodedPath(Default) == "/foo%2520bar"
    check "foo bar//../bif baz".encodedPath(Default) == "/bif%2520baz"
    check "/foo bar/bif/".encodedPath(Default) == "/foo%2520bar/bif/"
    check "/foo bar//../bif".encodedPath(S3) == "/foo%20bar//../bif"
    check "/foo bar//../bif/".encodedPath(S3) == "/foo%20bar//../bif/"

  test "encoded query":
    let
      cq = %* {
        "a": 1,
        "B": 2.0,
        "c": newJNull(),
        "d": newJBool(true),
        "3 4": "5,🙄",
      }
    check cq["a"].toQueryValue == "1"
    check cq["B"].toQueryValue == "2.0"
    check cq["c"].toQueryValue == ""
    check cq["d"].toQueryValue == "true"
    check cq["3 4"].toQueryValue == "5,🙄"
    check cq.encodedQuery == "3%204=5%2C%F0%9F%99%84&B=2.0&a=1&c=&d=true"
    check q.encodedQuery == "Action=ListUsers&Version=2010-05-08"

  test "encoded headers":
    var
      h: HttpHeaders = newHttpHeaders(heads)
      rheads = heads.reversed
      r: EncodedHeaders
    r = (signed: "content-type;host;x-amz-date",
         canonical: "content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:iam.amazonaws.com\nx-amz-date:20150830T123600Z\n")
    h = newHttpHeaders(heads)
    check r == h.encodedHeaders()
    h = newHttpHeaders(rheads)
    check r == h.encodedHeaders()

  test "signing algos":
    let
      pay = "sigv4 test"
      e = {
        "AWS4-HMAC-SHA256": "474fff1f1f31f629b3a8932f1020ad2e73bf82e08c96d5998de39d66c8867836",
        "AWS4-HMAC-SHA512": "1dee518b5b2479e9fa502c05d4726a40bade650adbc391da8f196797df0f5da62e0659ad0e5a91e185c4b047d7a2d6324fae493a0abdae7aa10b09ec8303f6fe",
      }.toTable
    check pay.hash(SHA256) == e[$SHA256]
    check pay.hash(SHA512) == e[$SHA512]
    check "".hash(SHA256) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    var
      mac = newHmac(SHA256Digest, "some key", "some data")
    check mac.toLowerHex == "92003059a722e7632fc06d79b2c682849aa17195b617580464d048e12242c844"
    mac.add "more data"
    check mac.toLowerHex == "d8758ca7f1f12439dafe3513ef0ee2d9fcda77d12d40721edb9c2d31b6ffc4e2"

  test "canonical request":
    discard """
    GET https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08 HTTP/1.1
Host: iam.amazonaws.com
Content-Type: application/x-www-form-urlencoded; charset=utf-8
X-Amz-Date: 20150830T123600Z
    """
    let
      h: HttpHeaders = newHttpHeaders(heads)
      canonical = canonicalRequest(HttpGet, url, q, h, "", normal, digest)
      x = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      y = "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
    check canonical == """GET
/
Action=ListUsers&Version=2010-05-08
content-type:application/x-www-form-urlencoded; charset=utf-8
host:iam.amazonaws.com
x-amz-date:20150830T123600Z

content-type;host;x-amz-date
""" & x
    check canonical.hash(digest) == y

  test "credential scope":
    let
      d = "20200101T55555555555"
      scope = credentialScope(region="Us-West-1", service="IAM", date=d)
      skope = credentialScope(region=region, service=service, date=date)
    check scope == "20200101/us-west-1/iam/aws4_request"
    check skope == "20150830/us-east-1/iam/aws4_request"

  test "string to sign":
    let
      h: HttpHeaders = newHttpHeaders(heads)
      req = canonicalRequest(HttpGet, url, q, h, "", normal, digest)
      x = "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
      scope = credentialScope(region=region, service=service, date=date)
      sts = stringToSign(req.hash(digest), scope, date=date, digest=digest)
    check req.hash(digest) == x
    check sts == """AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/iam/aws4_request
""" & x

  test "derive key":
    let
      key = deriveKey(SHA256Digest, secret, date=date,
                      region=region, service=service)
      x = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
    check x == key.toLowerHex

  test "calculate signature":
    let
      h: HttpHeaders = newHttpHeaders(heads)
      req = canonicalRequest(HttpGet, url, q, h, "", normal, digest)
      scope = credentialScope(region=region, service=service, date=date)
      sts = stringToSign(req.hash(digest), scope, date=date, digest=digest)
      key = deriveKey(SHA256Digest, secret, date=date,
                      region=region, service=service)
      x = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    check x == calculateSignature(key, sts)
    check x == calculateSignature(secret=secret, date=date, region=region,
                                  service=service, tosign=sts, digest=digest)
