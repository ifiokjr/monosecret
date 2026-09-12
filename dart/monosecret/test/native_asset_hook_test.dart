import 'package:test/test.dart';

import '../hook/build.dart';

void main() {
  const payload = 'monosecret-ffi-x86_64-unknown-linux-gnu-v1.2.3.so';
  const hash =
      '0123456789abcdef0123456789abcdef'
      '0123456789abcdef0123456789abcdef';

  group('parseChecksumSidecar', () {
    test('accepts the release sha256sum format', () {
      expect(parseChecksumSidecar('$hash  $payload\n', payload), hash);
      expect(parseChecksumSidecar('$hash *$payload\n', payload), hash);
    });

    test('rejects malformed and multi-entry sidecars', () {
      expect(
        () => parseChecksumSidecar('not-a-checksum  $payload\n', payload),
        throwsFormatException,
      );
      expect(
        () =>
            parseChecksumSidecar('$hash  $payload\n$hash  other.so\n', payload),
        throwsFormatException,
      );
    });

    test('rejects a checksum for a different asset', () {
      expect(
        () => parseChecksumSidecar('$hash  other.so\n', payload),
        throwsA(
          isA<FormatException>().having(
            (error) => error.message,
            'message',
            contains('other.so'),
          ),
        ),
      );
    });
  });

  group('payloadDependencyUri', () {
    test('keys the shared-cache payload by its verified hash', () {
      final uri = payloadDependencyUri(
        sharedOutputDirectory: Uri.file('/shared/build/'),
        expectedHash: hash,
        payloadName: payload,
      );

      expect(uri.toFilePath(), '/shared/build/monosecret/$hash/$payload');
    });

    test(
      'changes with the verified hash so new releases invalidate runners',
      () {
        final next = payloadDependencyUri(
          sharedOutputDirectory: Uri.file('/shared/build/'),
          expectedHash:
              'ffffffffffffffffffffffffffffffff'
              'ffffffffffffffffffffffffffffffff',
          payloadName: payload,
        );

        expect(
          next,
          isNot(
            payloadDependencyUri(
              sharedOutputDirectory: Uri.file('/shared/build/'),
              expectedHash: hash,
              payloadName: payload,
            ),
          ),
        );
      },
    );
  });
}
