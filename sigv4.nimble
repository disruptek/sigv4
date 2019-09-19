version = "1.0.0"
author = "disruptek"
description = "Amazon Web Services Signature Version 4"
license = "MIT"
requires "nim >= 0.20.0"
requires "nimcrypto >= 0.4.0"

task test, "Runs the test suite":
  exec "nim c -r sigv4.nim"
