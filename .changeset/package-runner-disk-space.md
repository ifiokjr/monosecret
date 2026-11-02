---
rust:monosecret: patch
---

# Free runner disk space before packaging

The packaging workflow now removes unused hosted-runner SDKs and Docker
images before installing its development environment. This avoids running
out of disk before the package validation steps can start.
