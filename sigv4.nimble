version = "1.0.7"
author = "disruptek"
description = "Amazon Web Services Signature Version 4"
license = "MIT"
requires "nim >= 0.20.2"

when defined(sigv4UseNimCrypto):
  requires "https://github.com/disruptek/nimcrypto#tinycc"
else:
  requires "https://github.com/OpenSystemsLab/hmac.nim < 1.0.0"

proc execCmd(cmd: string) =
  echo "execCmd:" & cmd
  exec cmd

proc execTest(test: string) =
  execCmd "nim c           -f -r " & test
  execCmd "nim c   -d:release -r " & test
  execCmd "nim c   -d:danger  -r " & test
  execCmd "nim cpp            -r " & test
  execCmd "nim cpp -d:danger  -r " & test
  when NimMajor >= 1 and NimMinor >= 1:
    execCmd "nim c   --gc:arc -r " & test
    execCmd "nim cpp --gc:arc -r " & test

task test, "run tests for travis":
  execTest("sigv4.nim")
