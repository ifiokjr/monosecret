import 'dart:io';

import 'package:monosecret/monosecret.dart';
import 'package:test/test.dart';

void main() {
  group('MonosecretConfig', () {
    test('uses conventional defaults', () {
      const config = MonosecretConfig();

      expect(config.path, 'monosecret.toml');
      expect(config.className, 'MonosecretSecrets');
    });

    test('accepts generated library options', () {
      const config = MonosecretConfig(
        path: 'config/monosecret.toml',
        className: 'AppSecrets',
      );

      expect(config.path, 'config/monosecret.toml');
      expect(config.className, 'AppSecrets');
    });
  });

  test('native ABI matches the Dart package', () {
    expect(abiVersion(), monosecretVersion);
  });

  test('filtered resolution ignores unrelated required secrets', () async {
    final directory = await Directory.systemTemp.createTemp(
      'monosecret_dart_filter_',
    );
    addTearDown(() => directory.delete(recursive: true));

    final manifest = File('${directory.path}/monosecret.toml');
    final dotenv = File('${directory.path}/.env');
    await manifest.writeAsString('''
[project]
name = "dart-filter"
revision = "1.0"

[groups]
backend = "Backend"
observability = "Observability"

[profiles.default]
DATABASE_URL = { description = "Database", required = true, groups = ["backend"] }
LOG_LEVEL = { description = "Logs", default = "info", required = false, groups = ["observability"] }
''');
    await dotenv.writeAsString('');

    final resolved = await Monosecret.builder()
        .withPath(manifest.path)
        .withProvider('dotenv://${dotenv.path}')
        .withReason('Dart filtered resolution test')
        .withGroups(['observability'])
        .load();
    addTearDown(resolved.close);

    expect(resolved.fields, {'LOG_LEVEL': 'info'});

    await expectLater(
      Monosecret.builder()
          .withPath(manifest.path)
          .withProvider('dotenv://${dotenv.path}')
          .withReason('Dart invalid filter test')
          .withInclude(['UNKNOWN'])
          .load(),
      throwsA(
        isA<MonosecretException>()
            .having((error) => error.kind, 'kind', 'io')
            .having(
              (error) => error.message,
              'message',
              contains("Included secret 'UNKNOWN'"),
            ),
      ),
    );
  });

  test('close removes native as_path temporary files', () async {
    final directory = await Directory.systemTemp.createTemp(
      'monosecret_dart_cleanup_',
    );
    addTearDown(() => directory.delete(recursive: true));

    final manifest = File('${directory.path}/monosecret.toml');
    final dotenv = File('${directory.path}/.env');
    await manifest.writeAsString('''
[project]
name = "dart-cleanup"
revision = "1.0"

[profiles.default]
TLS_CERT = { description = "Certificate", required = false, default = "certificate", as_path = true }
''');
    await dotenv.writeAsString('');

    final resolved = await Monosecret.builder()
        .withPath(manifest.path)
        .withProvider('dotenv://${dotenv.path}')
        .withReason('Dart as_path cleanup test')
        .load();
    addTearDown(resolved.close);
    final path = resolved.secrets['TLS_CERT']!.path!;

    expect(await File(path).exists(), isTrue);
    await resolved.close();
    expect(await File(path).exists(), isFalse);
  });

  test('close releases hidden composition as_path file dependencies', () async {
    final directory = await Directory.systemTemp.createTemp(
      'monosecret_dart_hidden_lease_',
    );
    addTearDown(() => directory.delete(recursive: true));

    final manifest = File('${directory.path}/monosecret.toml');
    final dotenv = File('${directory.path}/.env');
    await manifest.writeAsString('''
[project]
name = "dart-hidden-lease"
revision = "1.0"
require_reason = false

[profiles.default]
KEY = { description = "Hidden key file", default = "secret-bytes", as_path = true }
ARGS = { description = "Composed args", composed = "key=\${KEY}" }

[scopes.app]
secrets = ["ARGS"]
''');
    await dotenv.writeAsString('');

    final resolved = await Monosecret.builder()
        .withPath(manifest.path)
        .withProvider('dotenv://${dotenv.path}')
        .withScope('app')
        .load();
    addTearDown(resolved.close);

    expect(resolved.secrets.containsKey('KEY'), isFalse);
    final args = resolved.secrets['ARGS']!.value!;
    final hiddenPath = args.substring('key='.length);
    expect(await File(hiddenPath).exists(), isTrue);
    expect(await File(hiddenPath).readAsString(), 'secret-bytes');

    await resolved.close();
    expect(await File(hiddenPath).exists(), isFalse);
    // Repeated close is idempotent.
    await resolved.close();
  });

  test('missing required secrets use the domain exception', () async {
    final directory = await Directory.systemTemp.createTemp(
      'monosecret_dart_missing_',
    );
    addTearDown(() => directory.delete(recursive: true));

    final manifest = File('${directory.path}/monosecret.toml');
    final dotenv = File('${directory.path}/.env');
    await manifest.writeAsString('''
[project]
name = "dart-missing"
revision = "1.0"

[profiles.default]
API_TOKEN = { description = "API token", required = true }
''');
    await dotenv.writeAsString('');

    await expectLater(
      Monosecret.builder()
          .withPath(manifest.path)
          .withProvider('dotenv://${dotenv.path}')
          .withReason('Dart missing required test')
          .load(),
      throwsA(
        isA<MissingRequiredException>().having(
          (error) => error.missing,
          'missing',
          ['API_TOKEN'],
        ),
      ),
    );
  });
}
