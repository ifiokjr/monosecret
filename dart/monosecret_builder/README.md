# monosecret_builder

Build runner generator for typed Dart access to `monosecret.toml` manifests.

```dart
@MonosecretConfig(className: 'AppSecrets')
library app_secrets;

import 'package:monosecret/monosecret.dart';

part 'app_secrets.g.dart';
```

Run:

```sh
dart run build_runner build
```
