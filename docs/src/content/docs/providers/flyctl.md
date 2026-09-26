---
title: Fly.io provider name
description: The Fly.io provider uses the fly name and URI scheme in Monosecret 0.3+.
sidebar:
  hidden: true
---

# The Fly.io provider is named `fly`

:::note[Version compatibility]
The Fly.io `fly` provider is added in Monosecret 0.3.
:::

The pre-release `flyctl` provider name was replaced by `fly`. Use the
[`fly` provider guide](/providers/fly/) and configure Fly.io application
secrets with a `fly://APP` URI.

The provider still invokes the `flyctl` executable internally. Only the
Monosecret provider name and URI scheme changed.
