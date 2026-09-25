import 'dart:ffi';
import 'dart:io';

import 'package:monosecret/monosecret.dart';
import 'package:monosecret/src/client.dart' as client;
import 'package:monosecret/src/native_bindings.dart' as bindings;
import 'package:test/test.dart';

/// Inline-spec and caller-context tests for the versioned native call ABI.
///
/// The native-support probe result is cached per isolate, so every test in
/// this file runs in one file-local isolate and resets the probe override in
/// `setUp`/`tearDown`.
void main() {
  setUp(() {
    client.inlineSupportProbeForTest = () => true;
  });

  tearDown(() {
    client.inlineSupportProbeForTest = () => true;
  });

  group('CallerContext', () {
    test('omits absent fields from the request', () {
      const context = CallerContext(name: 'dart-test');

      expect(context.toRequest(), {'name': 'dart-test'});
    });

    test('serializes every provided field', () {
      const context = CallerContext(
        name: 'dart-test',
        version: '0.3.1',
        operation: 'credential_get',
        resource: 'example.com',
      );

      expect(context.toRequest(), {
        'name': 'dart-test',
        'version': '0.3.1',
        'operation': 'credential_get',
        'resource': 'example.com',
      });
    });
  });

  test('inline spec resolves through the versioned call ABI', () async {
    final directory = await _tempDir('monosecret_dart_inline_');
    final dotenv = File('${directory.path}/.env');
    await dotenv.writeAsString('INLINE_TOKEN = inline-value\n');

    final resolved = await Monosecret.builder()
        .withInlineSpec(_inlineSpec(), directory.path)
        .withProvider('dotenv://${dotenv.path}')
        .withReason('Dart inline spec test')
        .load();
    addTearDown(resolved.close);

    expect(resolved.fields, {'INLINE_TOKEN': 'inline-value'});
    expect(resolved.profile, 'default');
    expect(resolved.provider, 'dotenv://${dotenv.path}');
  });

  test('inline spec resolution prefers the spec over withPath', () async {
    final directory = await _tempDir('monosecret_dart_inline_path_');
    final dotenv = File('${directory.path}/.env');
    await dotenv.writeAsString('INLINE_TOKEN = inline-value\n');

    final resolved = await Monosecret.builder()
        // A nonexistent manifest must be ignored once the inline spec is set:
        // inline resolution cannot fall back to a filesystem manifest.
        .withPath('${directory.path}/does-not-exist.toml')
        .withInlineSpec(_inlineSpec(), directory.path)
        .withProvider('dotenv://${dotenv.path}')
        .withReason('Dart inline overrides path test')
        .load();
    addTearDown(resolved.close);

    expect(resolved.fields, {'INLINE_TOKEN': 'inline-value'});
  });

  test('withPath clears a previously set inline spec', () async {
    final directory = await _tempDir('monosecret_dart_inline_clear_');
    final dotenv = File('${directory.path}/.env');
    await dotenv.writeAsString('FILE_TOKEN = file-value\n');
    final manifest = File('${directory.path}/monosecret.toml');
    await manifest.writeAsString('''
[project]
name = "dart-inline-clear"
revision = "1.0"

[profiles.default]
FILE_TOKEN = { description = "File token", required = true }
''');

    final resolved = await Monosecret.builder()
        .withInlineSpec(_inlineSpec(), directory.path)
        .withPath(manifest.path)
        .withProvider('dotenv://${dotenv.path}')
        .withReason('Dart inline clear test')
        .load();
    addTearDown(resolved.close);

    expect(resolved.fields, {'FILE_TOKEN': 'file-value'});
  });

  test('inline spec rides on the report mode', () async {
    final directory = await _tempDir('monosecret_dart_inline_report_');
    final dotenv = File('${directory.path}/.env');
    await dotenv.writeAsString('INLINE_TOKEN = inline-value\n');

    final report = await Monosecret.builder()
        .withInlineSpec(_inlineSpec(), directory.path)
        .withProvider('dotenv://${dotenv.path}')
        .withReason('Dart inline report test')
        .report();

    final token = report.secrets.singleWhere((s) => s.name == 'INLINE_TOKEN');
    expect(token.status, 'resolved');
  });

  test('caller context rides on a plain resolve request', () async {
    final directory = await _tempDir('monosecret_dart_caller_');
    final manifest = File('${directory.path}/monosecret.toml');
    final dotenv = File('${directory.path}/.env');
    await manifest.writeAsString('''
[project]
name = "dart-caller"
revision = "1.0"

[profiles.default]
CALLER_TOKEN = { description = "Caller token", required = true }
''');
    await dotenv.writeAsString('CALLER_TOKEN = caller-value\n');

    final resolved = await Monosecret.builder()
        .withPath(manifest.path)
        .withProvider('dotenv://${dotenv.path}')
        .withReason('Dart caller test')
        .withCaller(
          const CallerContext(
            name: 'dart-test',
            version: '0.3.1',
            operation: 'credential_get',
          ),
        )
        .load();
    addTearDown(resolved.close);

    expect(resolved.fields, {'CALLER_TOKEN': 'caller-value'});
  });

  test('client resolve forwards the caller context', () async {
    final directory = await _tempDir('monosecret_dart_client_caller_');
    final manifest = File('${directory.path}/monosecret.toml');
    final dotenv = File('${directory.path}/.env');
    await manifest.writeAsString('''
[project]
name = "dart-client-caller"
revision = "1.0"

[profiles.default]
CALLER_TOKEN = { description = "Caller token", required = true }
''');
    await dotenv.writeAsString('CALLER_TOKEN = caller-value\n');

    const client = MonosecretClient();
    final resolved = await client.resolve(
      path: manifest.path,
      provider: 'dotenv://${dotenv.path}',
      reason: 'Dart client caller test',
      caller: const CallerContext(name: 'client-test'),
    );
    addTearDown(resolved.close);

    expect(resolved.fields, {'CALLER_TOKEN': 'caller-value'});
  });

  test('withCaller(null) removes a previously set caller', () async {
    final directory = await _tempDir('monosecret_dart_caller_clear_');
    final manifest = File('${directory.path}/monosecret.toml');
    final dotenv = File('${directory.path}/.env');
    await manifest.writeAsString('''
[project]
name = "dart-caller-clear"
revision = "1.0"

[profiles.default]
CALLER_TOKEN = { description = "Caller token", required = true }
''');
    await dotenv.writeAsString('CALLER_TOKEN = caller-value\n');

    const client = MonosecretClient();
    final resolved = await client
        .builder()
        .withPath(manifest.path)
        .withProvider('dotenv://${dotenv.path}')
        .withReason('Dart caller clear test')
        .withCaller(const CallerContext(name: 'temporary'))
        .withCaller(null)
        .load();
    addTearDown(resolved.close);

    expect(resolved.fields, {'CALLER_TOKEN': 'caller-value'});
  });

  test('invalid inline specs surface the native error envelope', () async {
    final directory = await _tempDir('monosecret_dart_inline_invalid_');

    await expectLater(
      Monosecret.builder()
          .withInlineSpec(const {
            'project': {'name': 'dart-invalid'},
            // Unknown field: the native inline-spec schema denies unknowns.
            'surprise': true,
            'profiles': {},
          }, directory.path)
          .withReason('Dart invalid inline test')
          .load(),
      throwsA(
        isA<MonosecretException>()
            .having((error) => error.kind, 'kind', 'invalid_request')
            .having((error) => error.message, 'message', contains('surprise')),
      ),
    );
  });

  test('the real probe detects a capable native library', () {
    // Exercises the production probe (no override) against the bundled
    // library, which exports monosecret_call.
    expect(client.probeInlineSupport(), isTrue);
    expect(client.callEntryPointsUsable(), isTrue);
  });

  test('the probe reports missing call entry points as unusable', () {
    // An older native library throws on the missing monosecret_call symbol.
    expect(
      client.callEntryPointsUsable(call: (_) => throw StateError('missing')),
      isFalse,
    );
  });

  test('decodeResponse rejects null native pointers', () {
    expect(
      () => bindings.decodeResponse(nullptr, symbol: 'monosecret_call'),
      throwsA(
        isA<StateError>().having(
          (error) => error.message,
          'message',
          'monosecret_call returned a null pointer.',
        ),
      ),
    );
    expect(
      () => bindings.decodeResponse(nullptr, symbol: 'monosecret_resolve'),
      throwsA(
        isA<StateError>().having(
          (error) => error.message,
          'message',
          'monosecret_resolve returned a null pointer.',
        ),
      ),
    );
  });

  test('a native library from a different release is rejected', () {
    expect(
      () => client.checkNativeAbiVersion('0.0.0'),
      throwsA(
        isA<MonosecretException>()
            .having((error) => error.kind, 'kind', 'version')
            .having(
              (error) => error.message,
              'message',
              contains('does not match Dart package version'),
            ),
      ),
    );
    // The matching version passes silently.
    expect(
      () => client.checkNativeAbiVersion(monosecretVersion),
      returnsNormally,
    );
  });

  test('client report forwards the caller context', () async {
    final directory = await _tempDir('monosecret_dart_client_report_');
    final manifest = File('${directory.path}/monosecret.toml');
    final dotenv = File('${directory.path}/.env');
    await manifest.writeAsString('''
[project]
name = "dart-client-report"
revision = "1.0"

[profiles.default]
REPORT_TOKEN = { description = "Report token", required = true }
''');
    await dotenv.writeAsString('REPORT_TOKEN = report-value\n');

    const monosecretClient = MonosecretClient();
    final report = await monosecretClient.report(
      path: manifest.path,
      provider: 'dotenv://${dotenv.path}',
      reason: 'Dart client report test',
      caller: const CallerContext(name: 'client-report-test'),
    );

    final token = report.secrets.singleWhere((s) => s.name == 'REPORT_TOKEN');
    expect(token.status, 'resolved');
  });

  test('inline specs require a capable native library', () async {
    var probes = 0;
    client.inlineSupportProbeForTest = () {
      probes += 1;

      return false;
    };

    final directory = await _tempDir('monosecret_dart_inline_capability_');
    final builder = Monosecret.builder()
        .withInlineSpec(_inlineSpec(), directory.path)
        .withReason('Dart capability test');

    await expectLater(
      builder.load(),
      throwsA(
        isA<MonosecretException>()
            .having((error) => error.kind, 'kind', 'capability')
            .having(
              (error) => error.message,
              'message',
              contains('predates inline specifications'),
            ),
      ),
    );

    // The probe result is cached: a second request must not re-probe.
    await expectLater(builder.report(), throwsA(isA<MonosecretException>()));
    expect(probes, 1);
  });
}

Map<String, Object?> _inlineSpec() => {
  'project': {'name': 'dart-inline'},
  'providers': {'env': 'dotenv://inline.env'},
  'profiles': {
    'default': {
      'secrets': {
        'INLINE_TOKEN': {
          'description': 'Inline token',
          'required': true,
          'providers': ['env'],
        },
      },
    },
  },
};

Future<Directory> _tempDir(String prefix) async {
  final directory = await Directory.systemTemp.createTemp(prefix);
  addTearDown(() => directory.delete(recursive: true));

  return directory;
}
