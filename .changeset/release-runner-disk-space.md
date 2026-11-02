---
rust:monosecret: patch
---

# Keep release preparation within runner disk space

Release preparation and tagging now free the hosted runner's unused SDK and image space before entering devenv. The full development environment otherwise exhausts the disk while building the musl toolchain, preventing the MonoChange bot from creating or refreshing its release PR.
