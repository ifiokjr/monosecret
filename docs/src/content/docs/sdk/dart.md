---
title: Dart SDK
description: Native server-side Dart access to Monosecret secrets
---

The `monosecret` Dart package (available since Monosecret 0.1) resolves secrets through the bundled `monosecret_ffi` C ABI. A separate `monosecret` CLI installation is not required at runtime.

## Supported environments

- Dart 3.10 or later
- Linux with glibc, macOS, or Windows
- x64 or ARM64 server applications

Android, iOS, Dart web, and Linux musl are not supported.

## Installation

```sh
dart pub add monosecret
```

The package's build hook downloads the matching native library from the same-version GitHub release and verifies its SHA-256 checksum before Dart bundles it as a code asset.

## Resolve secrets

```dart
import 'package:monosecret/monosecret.dart';

Future<void> main() async {
  final resolved = await Monosecret.builder()
      .withPath('monosecret.toml')
      .withProfile('production')
      .withProvider('env://')
      .withReason('Start the API server')
      .load();

  try {
    print(resolved.secrets['DATABASE_URL']?.usable);
  } finally {
    await resolved.close();
  }
}
```

Call `Resolved.close()` to remove temporary files created for `as_path` secrets.

## Value-free reports

```dart
final report = await Monosecret.builder()
    .withProfile('production')
    .withReason('Deployment preflight')
    .report();
```

Reports contain status and provenance without copying secret values into native buffers or Dart strings.

## Inline specifications and caller context (0.3+)

```dart
final resolved = await Monosecret.builder()
    .withInlineSpec({
      'project': {'name': 'my-app'},
      'profiles': {
        'default': {
          'secrets': {
            'TOKEN': {'description': 'API token', 'required': true},
          },
        },
      },
    }, '/project')
    .withProvider('dotenv://.env')
    .withCaller(
      const CallerContext(
        name: 'my-dart-app',
        version: '1.0.0',
        operation: 'startup',
      ),
    )
    .withReason('Start the API server')
    .load();
```

Inline resolution uses the versioned native call entry point and cannot fall
back to a filesystem manifest. An older native library raises a `capability`
`MonosecretException` instead. `withCaller` records the invoking integration
in audit records; it never satisfies a `require_reason` policy.

`withInlineSpec(spec, baseDir)` resolves strict inline-spec v1 declarations.
`baseDir` resolves relative provider paths — useful when the specification is
embedded inside the application and its providers reference files relative to
a known project directory.

## Filter resolution

```dart
final resolved = await Monosecret.builder()
    .withInclude(['DATABASE_URL'])
    .withGroups(['backend'])
    .withReason('Start backend workers')
    .load();
```

Includes and groups are combined as a union before required-secret validation.

## Convenience API

```dart
const client = MonosecretClient();

final token = await client.get(
  'API_TOKEN',
  profile: 'production',
  reason: 'Authenticate an upstream request',
);

final environment = await client.exportEnvironment(
  groups: ['backend'],
  reason: 'Configure the server process',
);
```

Prefer `resolve()` over `get()` or `exportEnvironment()` when using `as_path` so you can explicitly manage temporary-file lifetime.

## Generated typed access

Install the generator:

```sh
dart pub add --dev build_runner monosecret_builder
```

Declare a generated library:

```dart
@MonosecretConfig(className: 'AppSecrets')
library app_secrets;

import 'package:monosecret/monosecret.dart';

part 'app_secrets.g.dart';
```

Then run:

```sh
dart run build_runner build --delete-conflicting-outputs
```

Generated code contains only configuration shape. Values are resolved by the native library at runtime.

## Artifact and ABI safety

The Dart package checks that `monosecret_abi_version()` exactly matches its own package version and validates versioned resolve/report schemas. Release automation builds, checksums, and attests native libraries before publishing the Dart package.

Secret values still become Dart-managed strings and cannot be reliably zeroized. Prefer `report`, `no_values`, and `as_path` when the application does not need an in-memory value.
