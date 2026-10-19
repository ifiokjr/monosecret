---
"rust:monosecret":
  bump: none
  type: none
---

# Stop the passbolt provider tests from failing with "Text file busy"

The passbolt test fixture wrote its fake CLI script through a file handle that stayed open in this process. A subprocess forked by another test thread could inherit that handle, and running the script then failed with `ETXTBSY`. The fixture now writes a scratch file and renames it into place, the same approach the bws provider tests already use. Only test code changes.
