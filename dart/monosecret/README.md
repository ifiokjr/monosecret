# monosecret Dart SDK

Dart SDK for invoking Monosecret and loading secrets into Dart applications.

## Runtime client

```dart
import 'package:monosecret/monosecret.dart';

final client = MonosecretClient();
final databaseUrl = await client.get('DATABASE_URL', profile: 'development');
final environment = await client.exportEnvironment(include: ['DATABASE_URL']);
```

`exportEnvironment` uses `monosecret env --shell dotenv` and returns only resolved Monosecret secrets. `loadEnvironment` remains available for the older `monosecret run -- env` behavior.

## Typed generated SDK

Add the builder as a dev dependency:

```yaml
dependencies:
  monosecret: ^0.0.0

dev_dependencies:
  build_runner: ^2.8.0
  monosecret_builder: ^0.0.0
```

Create a library next to your application code:

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

Use generated enums and classes:

```dart
final secrets = await AppSecrets.load(profile: AppProfile.development);
print(secrets.databaseUrl);

final token = await MonosecretClient().getAppSecret(AppSecret.pubToken);
```
