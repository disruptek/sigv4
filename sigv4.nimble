version = "1.0.9"
author = "disruptek"
description = "Amazon Web Services Signature Version 4"
license = "MIT"
requires "nim >= 0.20.2"

when defined(sigv4UseNimCrypto):
  requires "https://github.com/cheatfate/nimcrypto < 1.0.0"
else:
  requires "https://github.com/jangko/nimSHA2 < 1.0.0"

proc execCmd(cmd: string) =
  echo "execCmd:" & cmd
  exec cmd

proc execTest(test: string) =
  when getEnv("GITHUB_ACTIONS", "false") != "true":
    execCmd "nim c -r -f " & test
    when (NimMajor, NimMinor) >= (1, 2):
      execCmd "nim cpp --gc:arc -d:danger -r " & test
  else:
    execCmd "nim c              -r " & test
    execCmd "nim cpp            -r " & test
    execCmd "nim c   -d:danger  -r " & test
    execCmd "nim cpp -d:danger  -r " & test
    when (NimMajor, NimMinor) >= (1, 2):
      execCmd "nim c --useVersion:1.0 -d:danger -r " & test
      execCmd "nim c   --gc:arc -d:danger -r " & test
      execCmd "nim cpp --gc:arc -d:danger -r " & test

task test, "run tests for ci":
  execTest("sigv4.nim")
  execTest("--define:sigv4UseNimCrypto sigv4.nim")
