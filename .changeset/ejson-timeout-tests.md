---
"rust:monosecret": patch
---

# ejson timeout tests no longer fail on a loaded machine

The two tests that prove a hung or exited `ejson` CLI is stopped at its timeout
read the stub's descendant-PID file with `unwrap`, and a loaded runner could
kill the process group before the shell wrote it — so the suite failed with "No
such file or directory" on a machine that was busy with something else. They now
wait for the file with a bounded retry, which keeps the assertion (the stub must
record its descendant, and the descendant must be gone) while removing the race,
and the exit-path test's timeout is generous because what it checks is the cost
relative to the deadline rather than how fast the stub runs.

No runtime behavior changes: the provider's timeout handling is untouched.
