import os
import httpcore
import json
import strutils
import uri
import algorithm
import sequtils
import tables
import times

import hmac

const
  dateISO8601 = initTimeFormat "yyyyMMdd"
  tightISO8601 = initTimeFormat "yyyyMMdd\'T\'HHmmss\'Z\'"

type
  PathNormal* = enum Default, S3
  SigningAlgo* = enum
    SHA256 = "AWS4-HMAC-SHA256"
    SHA512 = "AWS4-HMAC-SHA512"

proc encodedSegment(segment: string; passes: int): string =
  ## encode a segment 1+ times
  result = segment.encodeUrl(usePlus = false)
  if passes > 1:
    result = result.encodedSegment(passes - 1)

proc encodedComponents(path: string; passes: int): string =
  ## encode an entire path with a number of passes
  if '/' notin path:
    return path.encodedSegment(passes)
  let
    splat = path.splitPath
    tail = splat.tail.encodedSegment(passes)
  result = splat.head.encodedComponents(passes) & "/" & tail

proc encodedPath(path: string; style: PathNormal): string =
  ## normalize and encode a URI's path
  case style:
  of S3:
    result = path
    result = result.encodedComponents(passes=1)
  of Default:
    result = path.normalizedPath
    if path.endsWith("/"):
      result = result & "/"
    result = result.encodedComponents(passes=2)
  if not result.startsWith("/"):
    result = "/" & result

proc encodedPath(uri: Uri; style: PathNormal): string =
  ## normalize and encode a URI's path
  result = uri.path.encodedPath(style)

proc encodedQuery(input: openarray[tuple[key: string, val: string]]): string =
  ## encoded a series of key/value pairs as a query string
  let query = input.sortedByIt (it.key, it.val)
  for key, value in query.items:
    if result.len > 0:
      result &= "&"
    result &= encodeUrl(key, usePlus = false)
    result &= "="
    result &= encodeUrl(value, usePlus = false)

proc toQueryValue(node: JsonNode): string =
  assert node != nil
  result = case node.kind:
  of JString: node.getStr
  of JInt, JFloat, JBool: $node
  of JNull: ""
  else:
    raise newException(ValueError, $node.kind & " unsupported")

proc encodedQuery(node: JsonNode): string =
  ## convert a JsonNode into an encoded query string
  var query: seq[tuple[key: string, val: string]]
  assert node != nil and node.kind == JObject
  if node == nil or node.kind != JObject:
    raise newException(ValueError, "pass me a JObject")
  for k, v in node.pairs:
    query.add (key: k, val: v.toQueryValue)
  result = encodedQuery(query)

proc trimAll(s: string): string =
  ## remove surrounding whitespace and de-dupe internal spaces
  result = s.strip(leading=true, trailing=true)
  while "  " in result:
    result = result.replace("  ", " ")

proc encodedHeaders(headers: HttpHeaders): tuple[signed: string; canonical: string] =
  ## convert http headers into encoded header string
  var
    signed, canonical: string
    heads: seq[tuple[key: string, val: string]]
  if headers == nil:
    return (signed: "", canonical: "")
  for k, v in headers.table.pairs:
    heads.add (key: k.strip.toLowerAscii,
               val: v.map(trimAll).join(","))
  heads = heads.sortedByIt (it.key)
  for h in heads:
    if signed.len > 0:
      signed &= ";"
    signed &= h.key
    canonical &= h.key & ":" & h.val & "\n"
  result = (signed: signed, canonical: canonical)

proc hash(payload: string; digest: SigningAlgo): string =
  ## hash an arbitrary string using the given algorithm
  case digest:
  of SHA256:
    result = payload.hashSHA256.toHex
  of SHA512:
    result = payload.hashSHA512.toHex

proc canonicalRequest(meth: HttpMethod;
                      url: string;
                      query: JsonNode;
                      headers: HttpHeaders;
                      payload: string;
                      normalize: PathNormal = Default;
                      digest: SigningAlgo = SHA256): string =
  ## produce the canonical request for signing purposes
  let
    httpmethod = $meth
    uri = url.parseUri
    (signedHeaders, canonicalHeaders) = headers.encodedHeaders()

  result = httpmethod.toUpperAscii & "\n"
  result &= uri.encodedPath(normalize) & "\n"
  result &= query.encodedQuery() & "\n"
  result &= signedHeaders & "\n"
  result &= canonicalHeaders & "\n"
  result &= payload.hash(digest)

proc credentialScope(region: string; service: string; date= ""): string =
  ## combine region, service, and date into a scope
  var d = date[.. len("YYYMMDD")]
  if d == "":
    d = getTime().utc.format(dateISO8601)
  result = d / region.toLowerAscii / service.toLowerAscii / "aws4_request"

proc stringToSign(hash: string; scope: string; date= ""; digest: SigningAlgo = SHA256): string =
  ## combine signing algo, payload hash, credential scope, and date
  var d = date
  if d == "":
    d = getTime().utc.format(tightISO8601)
  assert d["YYYYMMDD".len] == 'T'
  assert d["YYYYMMDDTHHMMSS".len] == 'Z'
  result = $digest & "\n"
  result &= d[.. ("YYYYMMDDTHHMMSSZ".len-1)] & "\n"
  result &= scope & "\n"
  result &= hash

when isMainModule:
  import unittest

  suite "sig v4":
    setup:
      let
        q = %* {
          "a": 1,
          "B": 2.0,
          "c": newJNull(),
          "3 4": "5,🙄",
        }
        heads = @[("foo", "bar"), ("bif baz ", " boz     bop")]
        c = credentialScope(region="us-west-1", service="iam", date="20200202")
        pay = "sigv4 test"
        e = {
          "AWS4-HMAC-SHA256": "474fff1f1f31f629b3a8932f1020ad2e73bf82e08c96d5998de39d66c8867836",
          "AWS4-HMAC-SHA512": "1dee518b5b2479e9fa502c05d4726a40bade650adbc391da8f196797df0f5da62e0659ad0e5a91e185c4b047d7a2d6324fae493a0abdae7aa10b09ec8303f6fe",
        }.toTable
      var h: HttpHeaders = newHttpHeaders(heads)
    test "encoded segment":
      check "".encodedSegment(passes=1) == ""
      check "foo".encodedSegment(passes=1) == "foo"
      check "foo".encodedSegment(passes=2) == "foo"
      check "foo bar".encodedSegment(passes=1) == "foo%20bar"
      check "foo bar".encodedSegment(passes=2) == "foo%2520bar"
    test "encoded components":
      check "/".encodedComponents(passes=1) == "/"
      check "foo".encodedComponents(passes=1) == "foo"
      check "/foo/bar".encodedComponents(passes=1) == "/foo/bar"
      check "/foo/bar/".encodedComponents(passes=1) == "/foo/bar/"
      check "/foo bar".encodedComponents(passes=1) == "/foo%20bar"
      check "/foo bar/".encodedComponents(passes=2) == "/foo%2520bar/"
      check "foo bar".encodedComponents(passes=2) == "foo%2520bar"
      check "foo bar/bif".encodedComponents(passes=2) == "foo%2520bar/bif"
    test "encoded path":
      check "foo bar".encodedPath(Default) == "/foo%2520bar"
      check "foo bar//../bif baz".encodedPath(Default) == "/bif%2520baz"
      check "/foo bar/bif/".encodedPath(Default) == "/foo%2520bar/bif/"
      check "/foo bar//../bif".encodedPath(S3) == "/foo%20bar//../bif"
      check "/foo bar//../bif/".encodedPath(S3) == "/foo%20bar//../bif/"
    test "encoded query":
      check q.encodedQuery == "3%204=5%2C%F0%9F%99%84&B=2.0&a=1&c="
    test "encoded headers":
      var
        rheads = heads.reversed
        r: tuple[signed: string; canonical: string]
      r = (signed: "bif baz;foo", canonical: "bif baz:boz bop\nfoo:bar\n")
      h = newHttpHeaders(heads)
      check r == h.encodedHeaders()
      h = newHttpHeaders(rheads)
      check r == h.encodedHeaders()
    test "signing algos":
      check pay.hash(SHA256) == e[$SHA256]
      check pay.hash(SHA512) == e[$SHA512]
    test "canonical request":
      let
        digest = SHA512
        normal = S3
        canonical = canonicalRequest(HttpGet, "/foo/bar/..//bif/",
                                     q, h, pay, normal, digest)
      check canonical == """GET
/foo/bar/..//bif/
3%204=5%2C%F0%9F%99%84&B=2.0&a=1&c=
bif baz;foo
bif baz:boz bop
foo:bar

1dee518b5b2479e9fa502c05d4726a40bade650adbc391da8f196797df0f5da62e0659ad0e5a91e185c4b047d7a2d6324fae493a0abdae7aa10b09ec8303f6fe"""
    test "credential scope":
      let
        date = "2020010155555555555"
        scope = credentialScope(region="Us-West-1", service="IAM", date=date)
      check scope == "20200101/us-west-1/iam/aws4_request"

    test "string to sign":
      let
        digest = SHA512
        date = "20200202T010101Z"
        normal = S3
        req = canonicalRequest(HttpGet, "/foo/bar/",
                                     q, h, pay, normal, digest)
        scope = credentialScope(region="us-west-1", service="S3", date=date)
        sts = stringToSign(req.hash(digest), scope, date=date, digest=digest)
      check sts == """AWS4-HMAC-SHA512
20200202T010101Z
20200202/us-west-1/s3/aws4_request
d18bef886ba28e931de7cf40bca6b69d6b163eac7548e981f9578143cb445521bf54a4db0af7b141850a7ee4f246f1daab10eff9d2042c618a6737a09286fa9b"""
