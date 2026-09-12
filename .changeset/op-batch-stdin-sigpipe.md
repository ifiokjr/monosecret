---
"rust:monosecret": fix
---

# Resolution no longer dies on SIGPIPE when a provider CLI exits without draining stdin

The CLI restores SIGPIPE's default disposition (`monosecret check | head`), but
every provider that pipes data into a child CLI — `op item get` batch reads,
`op inject`, `pass insert`, `lpass add`, `pass-cli` — spawned the child and then
wrote to its stdin. If the child rejected the input and exited without draining
stdin (exactly how `op item get` refuses a batch with an ambiguous title), the
write could land after the child's exit and terminate monosecret with SIGPIPE
mid-resolution: no error message, no inject fallback, exit by signal. The window
is normally won by the writer, so regular CI passed; the slower
coverage-instrumented build on Linux reliably lost it.

Child stdin writes now run with SIGPIPE blocked on the writing thread (the
process disposition stays untouched, so sibling batch threads and shell pipes
keep their semantics) and a broken pipe is treated as the child's verdict: the
child's exit status and stderr flow through the existing error classification,
so an ambiguous-title batch still defers to the inject fallback. A regression
test drives a child that closes its read end without draining an oversized
batch, which pins the fix deterministically.
