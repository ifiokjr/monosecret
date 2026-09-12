import 'dart:convert';
import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart';
import 'package:hooks/hooks.dart';
import 'package:hooks/src/test.dart';
import 'package:monosecret/src/client.dart' as client;
import 'package:monosecret/src/version.dart';
import 'package:test/test.dart';

import '../hook/build.dart' as hook;

CodeAssetExtension _codeAssetExtension() => CodeAssetExtension(
  targetArchitecture: Architecture.current,
  targetOS: OS.current,
  linkModePreference: LinkModePreference.dynamic,
  macOS: OS.current == OS.macOS ? MacOSCodeConfig(targetVersion: 13) : null,
);

/// End-to-end scenarios for the release-download branch of the build hook.
///
/// The hook input does not change when a Monosecret release changes the
/// downloaded `monosecret-ffi-*` payload, so these tests serve fixture
/// payloads through a fake fetcher and assert that the build output and its
/// recorded dependencies track the served artifact. Without that invariant a
/// hooks runner can replay the previous release's library and every resolve
/// fails closed with `Native ABI version ... does not match Dart package
/// version ...`.
void main() {
  late _FakeReleaseFetcher fetcher;

  setUp(() {
    fetcher = _FakeReleaseFetcher();
    hook.ffiReleaseFetcher = fetcher;
  });

  tearDown(() {
    hook.ffiReleaseFetcher = const hook.HttpFfiReleaseFetcher();
  });

  test(
    'output asset and recorded dependency track the served release payload',
    () async {
      final dependencies = <Uri>[];
      final payloadContents = <String>[];

      Future<void> run() => testBuildHook(
        mainMethod: hook.main,
        extensions: [_codeAssetExtension()],
        check: (input, output) {
          final artifact = hook.ffiArtifactFor(
            input.config.code.targetOS,
            input.config.code.targetArchitecture,
          );
          final expectedDependency = _expectedDependency(
            input,
            artifact,
            fetcher,
          );
          dependencies.add(expectedDependency);
          payloadContents.add(
            File.fromUri(
              input.outputDirectory.resolve(artifact.libraryName),
            ).readAsStringSync(),
          );
          expect(output.dependencies, contains(expectedDependency));
        },
      );

      fetcher.payloadBody = 'monosecret-ffi-fixture-generation-1';
      await run();
      fetcher.payloadBody = 'monosecret-ffi-fixture-generation-2';
      await run();

      // The hook input was identical across both runs; only the served
      // release payload changed. Both the copied asset and the recorded
      // dependency must follow the artifact, or a runner replaying its cache
      // ships the previous release's library.
      expect(payloadContents, hasLength(2));
      expect(payloadContents[0], contains('generation-1'));
      expect(payloadContents[1], contains('generation-2'));
      expect(dependencies[1], isNot(dependencies[0]));
    },
  );

  test(
    'fails closed when the downloaded payload violates the sidecar',
    () async {
      fetcher.corruptPayload = true;

      await expectLater(
        testBuildHook(
          mainMethod: hook.main,
          extensions: [_codeAssetExtension()],
          check: (input, output) {},
        ),
        throwsStateError,
      );
    },
  );

  test('version mismatch points consumers at the stale build cache', () {
    expect(
      () => client.checkNativeAbiVersion('0.0.1'),
      throwsA(
        isA<Object>().having(
          (error) => error.toString(),
          'message',
          allOf(
            contains('0.0.1'),
            contains(monosecretVersion),
            contains('.dart_tool'),
          ),
        ),
      ),
    );
  });
}

Uri _expectedDependency(
  BuildInput input,
  hook.FfiArtifact artifact,
  _FakeReleaseFetcher fetcher,
) {
  final releaseTag = 'v$monosecretVersion';
  final payloadName =
      'monosecret-ffi-${artifact.target}-$releaseTag.${artifact.extension}';
  return hook.payloadDependencyUri(
    sharedOutputDirectory: input.outputDirectoryShared,
    expectedHash: sha256
        .convert(utf8.encode(fetcher.payloadFor(payloadName)))
        .toString(),
    payloadName: payloadName,
  );
}

class _FakeReleaseFetcher implements hook.FfiReleaseFetcher {
  String payloadBody = '';
  bool corruptPayload = false;
  int downloadCount = 0;

  String payloadFor(String payloadName) =>
      corruptPayload ? '$payloadBody-tampered' : payloadBody;

  @override
  Future<String> checksumText(Uri uri) async {
    final payloadName = _payloadName(uri);
    final served = corruptPayload
        ? sha256.convert(utf8.encode('not-the-served-payload')).toString()
        : sha256.convert(utf8.encode(payloadFor(payloadName))).toString();
    return '$served  $payloadName\n';
  }

  @override
  Future<void> downloadPayload(Uri uri, File destination) async {
    downloadCount++;
    await destination.writeAsString(payloadFor(_payloadName(uri)));
  }

  String _payloadName(Uri sidecarUri) {
    final stem = sidecarUri.pathSegments.last.replaceAll(
      RegExp(r'\.sha256$'),
      '',
    );
    final extension = stem.contains('apple-darwin')
        ? 'dylib'
        : stem.contains('windows-msvc')
        ? 'dll'
        : 'so';
    return '$stem.$extension';
  }
}
