import 'dart:convert';
import 'dart:isolate';

import 'package:meta/meta.dart';

import 'models.dart';
import 'native_bindings.dart';
import 'version.dart';

const _resolveSchemaVersion = 2;
const _reportSchemaVersion = 1;
const _nativeCallRequestVersion = 1;
const _inlineSpecSchemaVersion = 2;

/// Whether the bundled native library exposes the versioned `monosecret_call`
/// entry point. Probed once and cached; tests override
/// [inlineSupportProbeForTest] to cover both branches.
bool _inlineSupportProbed = false;
bool _inlineSupport = false;
bool Function() _inlineSupportProbe = probeInlineSupport;

/// Overrides the inline-support probe (testing only). Passing a probe also
/// resets the cached result so the next request re-evaluates it.
@visibleForTesting
set inlineSupportProbeForTest(bool Function() probe) {
  _inlineSupportProbe = probe;
  _inlineSupportProbed = false;
}

/// Probes the bundled native library for `monosecret_call` without touching
/// the filesystem: an unparsable request still yields an error envelope from
/// a capable library, while an older one fails the symbol lookup entirely.
@visibleForTesting
bool probeInlineSupport() => callEntryPointsUsable();

/// Whether the native `monosecret_call` entry point is usable.
///
/// An unparsable request still yields an error envelope from a capable
/// library, while an older one fails the symbol lookup entirely. [call]
/// replaces the native binding for tests so both branches are coverable.
@visibleForTesting
bool callEntryPointsUsable({String Function(String)? call}) {
  final callFn = call ?? nativeCall;
  try {
    callFn('{"not":"a call request"}');
    return true;
  } on Object {
    return false;
  }
}

bool _inlineSpecsSupported() {
  if (!_inlineSupportProbed) {
    _inlineSupport = _inlineSupportProbe();
    _inlineSupportProbed = true;
  }

  return _inlineSupport;
}

/// Entry point for native Monosecret resolution.
abstract final class Monosecret {
  static MonosecretBuilder builder() => MonosecretBuilder();
}

/// Guards that the bundled native library matches this Dart package.
@visibleForTesting
void checkNativeAbiVersion(String actual) {
  if (actual != monosecretVersion) {
    throw MonosecretException(
      'version',
      'Native ABI version $actual does not match Dart package version '
          '$monosecretVersion. The loaded native library was most likely '
          'replayed from a stale native-assets build cache by a Dart SDK that '
          'did not re-run the build hook. Delete the .dart_tool directory '
          'beside the package or workspace and rebuild so the bundled '
          '$monosecretVersion library is downloaded.',
    );
  }
}

/// Configures one native resolution request.
class MonosecretBuilder {
  final Map<String, Object?> _request = {};
  (Map<String, Object?>, String)? _inline;

  MonosecretBuilder withPath(String? path) {
    _inline = null;
    return _set('path', path);
  }

  /// Resolves a strict inline-spec v1 declaration at [baseDir]
  /// (Monosecret 0.20+).
  ///
  /// Inline resolution uses the versioned native call entry point, so an
  /// older native library cannot fall back to a filesystem manifest —
  /// calling [load] raises a `capability` [MonosecretException] instead.
  /// Setting [withPath] afterwards clears the inline spec.
  MonosecretBuilder withInlineSpec(Map<String, Object?> spec, String baseDir) {
    _request.remove('path');
    _inline = (spec, baseDir);
    return this;
  }

  MonosecretBuilder withProvider(String? provider) =>
      _set('provider', provider);

  MonosecretBuilder withProfile(String? profile) => _set('profile', profile);

  MonosecretBuilder withScope(String? scope) => _set('scope', scope);

  MonosecretBuilder withReason(String? reason) => _set('reason', reason);

  /// Identifies the invoking software integration in audit records
  /// (Monosecret 0.20+). Never satisfies a `require_reason` policy.
  MonosecretBuilder withCaller(CallerContext? caller) {
    if (caller == null) {
      _request.remove('caller');
    } else {
      _request['caller'] = caller.toRequest();
    }

    return this;
  }

  MonosecretBuilder withNoValues([bool noValues = true]) =>
      _set('no_values', noValues);

  MonosecretBuilder withInclude(Iterable<String> include) =>
      _set('include', include.toList(growable: false));

  MonosecretBuilder withGroups(Iterable<String> groups) =>
      _set('groups', groups.toList(growable: false));

  /// Resolves secret values through the bundled native library.
  Future<Resolved> load() async {
    final response = await _dispatch(
      kind: 'resolve',
      expectedSchemaVersion: _resolveSchemaVersion,
    );

    return parseResolved(response);
  }

  /// Produces a value-free resolution report.
  Future<ResolutionReport> report() async {
    final response = await _dispatch(
      kind: 'report',
      expectedSchemaVersion: _reportSchemaVersion,
      mode: 'report',
    );

    return parseReport(response);
  }

  /// Builds the native request for this builder.
  ///
  /// Returns the request document and whether it must go through the
  /// versioned `monosecret_call` entry point (inline specs cannot fall back
  /// to the legacy `monosecret_resolve` symbol).
  (Map<String, Object?>, bool) _nativeRequest({String? mode}) {
    final options = {..._request, if (mode != null) 'mode': mode};
    final inline = _inline;
    if (inline == null) {
      return (options, false);
    }

    final (spec, baseDir) = inline;
    return (
      {
        'request_version': _nativeCallRequestVersion,
        'operation': 'resolve',
        'source': {
          'kind': 'inline',
          'spec_version': _inlineSpecSchemaVersion,
          'base_dir': baseDir,
          'spec': spec,
        },
        'options': options,
      },
      true,
    );
  }

  Future<Map<String, Object?>> _dispatch({
    required String kind,
    required int expectedSchemaVersion,
    String? mode,
  }) async {
    final (request, versioned) = _nativeRequest(mode: mode);
    if (versioned && !_inlineSpecsSupported()) {
      throw const MonosecretException(
        'capability',
        'the loaded native library predates inline specifications; upgrade '
            'the monosecret Dart package so its bundled library matches '
            '(Monosecret 0.20+)',
      );
    }

    checkNativeAbiVersion(nativeAbiVersion());

    final requestJson = jsonEncode(request);
    final responseJson = await Isolate.run(
      () => versioned ? nativeCall(requestJson) : nativeResolve(requestJson),
    );
    final decoded = jsonDecode(responseJson);

    return parseEnvelope(
      decoded,
      kind: kind,
      expectedSchemaVersion: expectedSchemaVersion,
    );
  }

  MonosecretBuilder _set(String key, Object? value) {
    if (value == null) {
      _request.remove(key);
    } else {
      _request[key] = value;
    }

    return this;
  }
}

/// Convenience client over the native builder API.
class MonosecretClient {
  const MonosecretClient();

  MonosecretBuilder builder() => Monosecret.builder();

  Future<Resolved> resolve({
    String? path,
    String? profile,
    String? provider,
    String? scope,
    String? reason,
    CallerContext? caller,
    Iterable<String> include = const [],
    Iterable<String> groups = const [],
    bool noValues = false,
  }) {
    return builder()
        .withPath(path)
        .withProfile(profile)
        .withProvider(provider)
        .withScope(scope)
        .withReason(reason)
        .withCaller(caller)
        .withInclude(include)
        .withGroups(groups)
        .withNoValues(noValues)
        .load();
  }

  Future<ResolutionReport> report({
    String? path,
    String? profile,
    String? provider,
    String? scope,
    String? reason,
    CallerContext? caller,
    Iterable<String> include = const [],
    Iterable<String> groups = const [],
  }) {
    return builder()
        .withPath(path)
        .withProfile(profile)
        .withProvider(provider)
        .withScope(scope)
        .withReason(reason)
        .withCaller(caller)
        .withInclude(include)
        .withGroups(groups)
        .report();
  }

  /// Resolves one named secret.
  ///
  /// Prefer [resolve] for an `as_path` secret so its temporary file can be
  /// closed explicitly after use.
  Future<String> get(
    String name, {
    String? profile,
    String? provider,
    String? file,
    String? scope,
    String? reason,
  }) async {
    final resolved = await resolve(
      path: file,
      profile: profile,
      provider: provider,
      scope: scope,
      reason: reason,
      include: [name],
    );
    final secret = resolved.secrets[name];
    final value = secret?.usable;

    if (value == null) {
      await resolved.close();
      throw MonosecretException(
        'missing_secret',
        'Secret $name did not resolve to a value.',
      );
    }

    if (secret!.asPath) {
      return value;
    }

    await resolved.close();
    return value;
  }

  /// Resolves selected secrets into a flat environment map.
  ///
  /// Prefer [resolve] when using `as_path` so the returned [Resolved] can be
  /// closed explicitly after its temporary files are no longer needed.
  Future<Map<String, String>> exportEnvironment({
    Iterable<String> include = const [],
    Iterable<String> groups = const [],
    String? profile,
    String? provider,
    String? file,
    String? scope,
    String? reason,
  }) async {
    final resolved = await resolve(
      path: file,
      profile: profile,
      provider: provider,
      scope: scope,
      reason: reason,
      include: include,
      groups: groups,
    );
    final environment = <String, String>{
      for (final entry in resolved.fields.entries)
        if (entry.value != null) entry.key: entry.value!,
    };

    if (resolved.secrets.values.every((secret) => !secret.asPath)) {
      await resolved.close();
    }

    return environment;
  }
}

/// Returns the version exported by the bundled native library.
String abiVersion() => nativeAbiVersion();
