import std/os
import std/httpcore
import std/json
import std/strutils
import std/uri
import std/algorithm
import std/sequtils
import std/tables
import std/times

when defined(sigv4UseNimCrypto):
  import nimcrypto/sha2 as sha
  import nimcrypto/hash as md
  import nimcrypto/hmac as hmac

  type
    MDigest256 = md.MDigest[256]
    MDigest512 = md.MDigest[512]

    SHA256Digest = sha.sha256
    SHA512Digest = sha.sha512

  func computeSHA256(s: string): MDigest256 = md.digest(SHA256Digest, s)
  func computeSHA512(s: string): MDigest512 = md.digest(SHA512Digest, s)

  func newHmac(H: typedesc; key: string; data: string): auto =
    result = hmac.hmac(H, key, data)

  func add(key: var MDigest256; data: string) =
    key = hmac.hmac(SHA256Digest, key.data, data)

  func add(key: var MDigest512; data: string) =
    key = hmac.hmac(SHA512Digest, key.data, data)

else:
  import nimSHA2 as sha

  type
    MDigest256 = SHA256Digest
    MDigest512 = SHA512Digest

  # algo from https://github.com/OpenSystemsLab/hmac.nim/blob/master/hmac.nim
  # (rewritten to taste)
  proc hmac[T](key: string; data: string): T =
    const
      oxor = 0x5c
      ixor = 0x36

    when T is MDigest256:
      let hash = computeSHA256
      const ds = 32
      const bs = ds * 2

    when T is MDigest512:
      let hash = computeSHA512
      const ds = 64
      const bs = ds * 2

    var work = newSeq[uint8](bs)         # nicely typed bytes, yum!
    var inputs = newString(bs)           # inputs = block size
    var output = newString(bs + ds)      # output = block size + digest size

    # if it's larger than the block size, hash the key to shrink it
    let key = if len(key) > bs: $hash(key) else: key

    # copy the key over the work
    copyMem addr work[0], unsafeAddr key[0], len(key)

    # take the key and xor it against output, input constants
    for i, w in work.pairs:
      output[i] = char(w xor oxor)
      inputs[i] = char(w xor ixor)

    # add a hash of input + data to the end of the output
    let tail = hash(inputs & data)
    copyMem addr output[bs], unsafeAddr tail[0], len(tail)

    # the final result is a hash of the entire output
    result = hash(output)

  func newHmac(H: typedesc; key: string; data: string): auto =
    when H is SHA256Digest: result = hmac[MDigest256](key, data)
    when H is SHA512Digest: result = hmac[MDigest512](key, data)

  func add[H](key: var H; data: string) =
    key = hmac[H]($key, data)

const
  dateISO8601 = initTimeFormat "yyyyMMdd"
  basicISO8601 = initTimeFormat "yyyyMMdd\'T\'HHmmss\'Z\'"

type
  DateFormat = enum JustDate, DateAndTime
  PathNormal* = enum
    Default ## normalize paths to dereference `.` and `..` and de-dupe `/`
    S3 ## do not normalize paths, and perform one less pass of escaping
  SigningAlgo* = enum
    SHA256 = "AWS4-HMAC-SHA256"
    SHA512 = "AWS4-HMAC-SHA512"
    UnsignedPayload = "UNSIGNED-PAYLOAD"
  DigestTypes = MDigest256 or MDigest512
  EncodedHeaders* = tuple[signed: string; canonical: string]
  KeyValue = tuple[key: string; val: string]

proc encodedSegment(segment: string; passes: int): string =
  ## encode a segment 1+ times
  result = segment.encodeUrl(usePlus = false)
  if passes > 1:
    result = result.encodedSegment(passes - 1)

proc safeSplitPath(path: string): tuple[head, tail: string] =
  ## a split path that won't change with nim versions
  var sepPos = -1
  for i in countdown(len(path)-1, 0):
    if path[i] in {DirSep, AltSep}:
      sepPos = i
      break
  if sepPos >= 0:
    result.head = substr(path, 0, sepPos-1)
    result.tail = substr(path, sepPos+1)
  else:
    result.head = ""
    result.tail = path

proc encodedComponents(path: string; passes: int): string =
  ## encode an entire path with a number of passes
  if '/' notin path:
    return path.encodedSegment(passes)
  let
    splat = path.safeSplitPath
    tail = splat.tail.encodedSegment(passes)
  result = splat.head.encodedComponents(passes) & "/" & tail

proc encodedPath(path: string; style: PathNormal): string =
  ## normalize and encode a URI's path
  case style
  of S3:
    result = path
    result = result.encodedComponents(passes=1)
  of Default:
    result = path.normalizedPath
    when DirSep != '/':
      result = result.replace(DirSep, '/')
    if path.endsWith("/") and not result.endsWith("/"):
      result = result & "/"
    result = result.encodedComponents(passes=2)
  if not result.startsWith("/"):
    result = "/" & result

proc encodedPath(uri: Uri; style: PathNormal): string =
  ## normalize and encode a URI's path
  result = uri.path.encodedPath(style)

proc encodedQuery(input: openArray[KeyValue]): string =
  ## encoded a series of key/value pairs as a query string
  let
    query = input.sortedByIt (it.key, it.val)
  for q in query.items:
    if result.len > 0:
      result.add "&"
    result.add encodeUrl(q.key, usePlus = false)
    result.add "="
    result.add encodeUrl(q.val, usePlus = false)

proc toQueryValue(node: JsonNode): string =
  ## render a json node as a query string value
  assert node != nil
  if node == nil:
    raise newException(ValueError, "pass me a JsonNode")
  result = case node.kind
  of JString:
    node.getStr
  of JInt, JFloat, JBool:
    $node
  of JNull:
    ""
  else:
    raise newException(ValueError, $node.kind & " unsupported")

proc encodedQuery(node: JsonNode): string =
  ## convert a JsonNode into an encoded query string
  var query: seq[KeyValue]
  assert node != nil and node.kind == JObject
  if node == nil or node.kind != JObject:
    raise newException(ValueError, "pass me a JObject")
  for q in node.pairs:
    query.add (key: q.key, val: q.val.toQueryValue)
  result = encodedQuery(query)

proc normalizeUrl*(url: string; query: JsonNode; normalize: PathNormal = Default): Uri =
  ## reorder and encode path and query components of a url
  result = url.parseUri
  result.path = result.path.encodedPath(normalize)
  result.query = query.encodedQuery
  result.anchor = ""

proc trimAll(s: string): string =
  ## remove surrounding whitespace and de-dupe internal spaces
  result = s.strip(leading=true, trailing=true)
  while "  " in result:
    result = result.replace("  ", " ")

# a hack to work around nim 0.20 -> 1.0 interface change
template isEmptyAnyVersion(h: HttpHeaders): bool =
  when compiles(h.isEmpty):
    h.isEmpty
  else:
    h == nil

proc encodedHeaders(headers: HttpHeaders): EncodedHeaders =
  ## convert http headers into encoded header string
  var
    signed, canonical: string
    heads: seq[KeyValue]
  if headers.isEmptyAnyVersion:
    return (signed: "", canonical: "")
  # i know it's deprecated, but there's no reasonable replacement (yet)
  # https://github.com/nim-lang/Nim/issues/12211
  for h in headers.table.pairs:
    heads.add (key: h[0].strip.toLowerAscii,
               val: h[1].map(trimAll).join(","))
  heads = heads.sortedByIt (it.key)
  for h in heads:
    if signed.len > 0:
      signed &= ";"
    signed &= h.key
    canonical &= h.key & ":" & h.val & "\n"
  result = (signed: signed, canonical: canonical)

proc signedHeaders*(headers: HttpHeaders): string =
  ## calculate the list of signed headers
  var encoded = headers.encodedHeaders
  result = encoded.signed

when defined(sigv4UseNimCrypto):
  when defined(nimcryptoLowercase):
    proc toLowerHex(digest: DigestTypes): string =
      result = $digest
  else:
    proc toLowerHex(digest: DigestTypes): string =
      {.hint: "sigv4: set -d:nimcryptoLowercase".}
      # ...in order to optimize out the following call...
      result = toLowerAscii($digest)
else:
  proc toLowerHex(digest: DigestTypes): string =
    result = toLowerAscii(digest.toHex)

when defined(debug):
  converter toString(digest: DigestTypes): string = digest.toLowerHex

proc hash*(payload: string; digest: SigningAlgo): string =
  ## hash an arbitrary string using the given algorithm
  case digest
  of SHA256: result = computeSHA256(payload).toLowerHex
  of SHA512: result = computeSHA512(payload).toLowerHex
  of UnsignedPayload: result = $UnsignedPayload

proc canonicalRequest*(meth: HttpMethod;
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
    heads = headers.encodedHeaders()

  result = httpmethod.toUpperAscii & "\n"
  result.add uri.encodedPath(normalize) & "\n"
  result.add query.encodedQuery() & "\n"
  result.add heads.canonical & "\n"
  result.add heads.signed & "\n"
  result.add (if payload == "UNSIGNED-PAYLOAD": payload else: hash(payload, digest))

template assertDateLooksValid(d: string; format: DateFormat) =
  when not defined(release):
    case format
    of JustDate:
      if d.len > "YYYYMMDD".len:
        assert d["YYYYMMDD".len] == 'T'
      else:
        assert d.len == "YYYYMMDD".len
    of DateAndTime:
      if d.len > "YYYYMMDDTHHMMSS".len:
        assert d["YYYYMMDDTHHMMSS".len] == 'Z'
      else:
        assert d.len == "YYYYMMDDTHHMMSSZ".len

proc makeDateTime*(date: string = ""): string =
  ## produce a date+time string as found in stringToSign, eg. YYYYMMDDTHHMMSSZ
  if date == "":
    result = getTime().utc.format(basicISO8601)
  else:
    assertDateLooksValid(date, DateAndTime)
    result = date[date.low .. ("YYYYMMDDTHHMMSSZ".len-1)]

proc makeDate*(date: string = ""): string =
  ## produce a date string as required for credentialScope, eg. YYYYMMDD
  if date == "":
    result = getTime().utc.format(dateISO8601)
  else:
    assertDateLooksValid(date, JustDate)
    result = date[date.low .. ("YYYYMMDD".len-1)]

proc credentialScope*(region: string; service: string; date= ""): string =
  ## combine region, service, and date into a scope
  let d = date.makeDate
  result = d / region.toLowerAscii / service.toLowerAscii / "aws4_request"
  when DirSep != '/':
    result = result.replace(DirSep, '/')

proc stringToSign*(hash: string; scope: string; date= ""; digest: SigningAlgo = SHA256): string =
  ## combine signing algo, payload hash, credential scope, and date
  result = $digest & "\n"
  result.add date.makeDateTime & "\n"
  result.add scope & "\n"
  result.add hash

proc deriveKey(H: typedesc; secret: string; date: string;
               region: string; service: string): auto =
  ## compute the signing key for a subsequent signature
  result = newHmac(H, "AWS4" & secret, date.makeDate)
  result.add region.toLowerAscii
  result.add service.toLowerAscii
  result.add "aws4_request"

proc calculateSignature(key: DigestTypes; tosign: string): string =
  var key = key
  key.add tosign
  result = key.toLowerHex

proc calculateSignature*(secret: string; date: string; region: string;
                         service: string; tosign: string;
                         digest: SigningAlgo = SHA256): string =
  ## compute a signature using secret, string-to-sign, and other details
  case digest
  of SHA256:
    var key = deriveKey(SHA256Digest, secret, date, region, service)
    key.add tosign
    result = key.toLowerHex
  of SHA512:
    var key = deriveKey(SHA512Digest, secret, date, region, service)
    key.add tosign
    result = key.toLowerHex
