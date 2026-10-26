//! Hot-path benchmarks compared against the base branch by the `perf` CI job.
//!
//! Every benchmark here is self-contained: specs are generated in memory, the
//! only provider touched is `env`, and `HOME`/`XDG_CONFIG_HOME` point at a
//! scratch directory so a run can never read a developer's real global config,
//! cache, or audit log. Run locally with
//! `cargo bench -p monosecret --no-default-features --features cli,__bench`.

use std::hint::black_box;
use std::time::Duration;

use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use criterion::criterion_group;
use criterion::criterion_main;
use monosecret::ProviderValue;
use monosecret::SecretBytes;
use monosecret::Secrets;
use monosecret::Spec;
use monosecret::bench_support::Shell;
use monosecret::bench_support::cache_entry_is_fresh;
use monosecret::bench_support::encode_cache_entry;
use monosecret::bench_support::render_shell;
use monosecret::codegen::build_ir;
use monosecret::resolve_json;
use tempfile::TempDir;

/// Secrets declared in the resolution benchmarks' profile.
const RESOLVED_SECRETS: usize = 40;

/// A `monosecret.toml` with `secrets` declarations in `default` and
/// `extra_profiles` more profiles that each override a quarter of them.
fn spec_toml(secrets: usize, extra_profiles: usize) -> String {
	use std::fmt::Write as _;

	let mut source =
		String::from("[project]\nname = \"bench\"\nrevision = \"1.0\"\n\n[profiles.default]\n");
	for index in 0..secrets {
		writeln!(
			source,
			"BENCH_SECRET_{index} = {{ description = \"Benchmark secret {index}\", required = {} }}",
			index % 3 != 0
		)
		.expect("writing to a String cannot fail");
	}
	for profile in 0..extra_profiles {
		write!(source, "\n[profiles.profile_{profile}]\n")
			.expect("writing to a String cannot fail");
		for index in (0..secrets).step_by(4) {
			writeln!(
				source,
				"BENCH_SECRET_{index} = {{ default = \"profile-{profile}-{index}\" }}"
			)
			.expect("writing to a String cannot fail");
		}
	}
	source
}

/// Points every home-relative lookup at a scratch directory for the life of
/// the returned guard, so nothing on the machine running the benchmark leaks
/// into — or is touched by — the measurements.
fn isolated_home() -> TempDir {
	let home = tempfile::tempdir().expect("scratch home directory");
	// SAFETY: benchmarks run on one thread and no other thread has started yet.
	unsafe {
		std::env::set_var("HOME", home.path());
		std::env::set_var("XDG_CONFIG_HOME", home.path().join("config"));
		std::env::set_var("XDG_STATE_HOME", home.path().join("state"));
		std::env::set_var("XDG_CACHE_HOME", home.path().join("cache"));
		for index in 0..RESOLVED_SECRETS {
			std::env::set_var(format!("BENCH_SECRET_{index}"), format!("value-{index}"));
		}
	}
	home
}

fn resolving_secrets(source: &str) -> Secrets {
	let spec = Spec::from_toml(source).expect("benchmark spec parses");
	let mut secrets = Secrets::from_spec(spec).expect("benchmark spec loads");
	secrets.set_provider("env");
	secrets.set_profile("default");
	secrets
}

fn bench_spec_parse(c: &mut Criterion) {
	let mut group = c.benchmark_group("spec_parse");
	for (label, secrets, profiles) in [("small", 12, 1), ("large", 200, 3)] {
		let source = spec_toml(secrets, profiles);
		group.throughput(Throughput::Bytes(source.len() as u64));
		group.bench_with_input(BenchmarkId::from_parameter(label), &source, |b, source| {
			b.iter(|| Spec::from_toml(black_box(source)).expect("fixture parses"));
		});
	}
	group.finish();
}

fn bench_manifest_and_codegen(c: &mut Criterion) {
	let _home = isolated_home();
	let source = spec_toml(200, 3);
	let spec = Spec::from_toml(&source).expect("fixture parses");
	let mut group = c.benchmark_group("codegen");
	group.bench_function("build_ir_200", |b| b.iter(|| build_ir(black_box(&spec))));
	group.finish();

	let secrets = Secrets::from_spec(spec).expect("fixture loads");
	let mut group = c.benchmark_group("manifest");
	group.bench_function("compose_200", |b| b.iter(|| secrets.manifest()));
	group.finish();
}

fn bench_resolve(c: &mut Criterion) {
	let home = isolated_home();
	let source = spec_toml(RESOLVED_SECRETS, 0);
	let secrets = resolving_secrets(&source);
	let warm = secrets
		.resolve()
		.expect("every benchmark secret resolves from env");
	assert_eq!(
		warm.secrets.len(),
		RESOLVED_SECRETS,
		"resolution must cover the whole profile before it is measured"
	);
	let mut group = c.benchmark_group("resolve");
	group.bench_function("env_40", |b| {
		b.iter(|| secrets.resolve().expect("resolves"));
	});

	let manifest_path = home.path().join("monosecret.toml");
	std::fs::write(&manifest_path, &source).expect("write fixture manifest");
	let request = serde_json::json!({
		"path": manifest_path,
		"provider": "env",
		"profile": "default",
	})
	.to_string();
	let response: serde_json::Value =
		serde_json::from_str(&resolve_json(&request)).expect("resolve_json returns JSON");
	assert!(
		response.get("error").is_none(),
		"resolve_json must succeed before it is measured: {response}"
	);
	group.bench_function("json_env_40", |b| {
		b.iter(|| resolve_json(black_box(&request)));
	});
	group.finish();
}

fn bench_cache_envelope(c: &mut Criterion) {
	let value = ProviderValue::new(SecretBytes::from_slice(&[0x5a; 64]), None);
	let fingerprint = "env:bench:default";
	let mut group = c.benchmark_group("cache");
	group.bench_function("encode", |b| {
		b.iter(|| encode_cache_entry("bench", "default", 600, fingerprint, black_box(&value)));
	});

	let stored = encode_cache_entry("bench", "default", 600, fingerprint, &value).expect("encodes");
	group.bench_function("decode_fresh", |b| {
		b.iter(|| cache_entry_is_fresh(black_box(&stored), "bench", "default", fingerprint, 600));
	});
	group.finish();
}

fn bench_shell_render(c: &mut Criterion) {
	let pairs: Vec<(String, String)> = (0..50)
		.map(|index| {
			(
				format!("BENCH_SECRET_{index}"),
				format!("value with 'quotes' and $igns {index}"),
			)
		})
		.collect();
	let mut group = c.benchmark_group("shell_render");
	for shell in [Shell::Bash, Shell::Github, Shell::Powershell] {
		group.bench_with_input(
			BenchmarkId::from_parameter(shell.as_str()),
			&pairs,
			|b, pairs| {
				b.iter(|| render_shell(shell, black_box(pairs)));
			},
		);
	}
	group.finish();
}

fn configure() -> Criterion {
	Criterion::default()
		.warm_up_time(Duration::from_secs(1))
		.measurement_time(Duration::from_secs(3))
		.sample_size(60)
		.noise_threshold(0.05)
}

criterion_group! {
	name = hot_paths;
	config = configure();
	targets = bench_spec_parse, bench_manifest_and_codegen, bench_resolve, bench_cache_envelope, bench_shell_render
}
criterion_main!(hot_paths);
