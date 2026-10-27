---
rust:monosecret: feat
---

# Chain the audit log so edits to history are detectable

Every audit entry now records the SHA-256 digest of its own content and
the digest of the entry before it, and `monosecret audit --verify` walks
the log recomputing every digest: editing an entry, reordering entries,
or removing one from the middle leaves a break reported by line number.
A new process continues the chain of the log it opens, entries written
before the chain existed are tolerated as an unhashed prefix, and the
restart the size cap performs counts as a new chain start rather than a
break — deleting the tail or the whole file remains indistinguishable
from those, which the docs state plainly, as does the fact that an
unkeyed chain catches partial edits rather than a full rewrite by an
attacker with write access to the log.
