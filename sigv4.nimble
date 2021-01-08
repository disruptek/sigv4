version = "1.0.11"
author = "disruptek"
description = "Amazon Web Services Signature Version 4"
license = "MIT"

when getEnv("GITHUB_ACTIONS", "false") != "true":
  when defined(sigv4UseNimCrypto):
    requires "https://github.com/cheatfate/nimcrypto >= 0.5.4 & < 1.0.0"
  else:
    requires "https://github.com/jangko/nimSHA2 < 1.0.0"
else:
  # just require everything for CI purposes
  requires "https://github.com/cheatfate/nimcrypto >= 0.5.4 & < 1.0.0"
  requires "https://github.com/jangko/nimSHA2 < 1.0.0"

when not defined(release):
  requires "https://github.com/disruptek/testes >= 0.7.8 & < 1.0.0"

task test, "run unit testes":
  when defined(windows):
    exec "testes.cmd"
  else:
    exec "testes"
    exec "testes --define:sigv4UseNimCrypto"
