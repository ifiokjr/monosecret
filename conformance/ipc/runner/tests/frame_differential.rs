use monosecret_rpc::frame::FrameDecoder;
use proptest::prelude::*;

fn reference_decode(bytes: &[u8], limit: usize) -> Result<Vec<Vec<u8>>, ()> {
	let mut frames = Vec::new();

	for line in bytes.split_inclusive(|byte| *byte == b'\n') {
		let Some(payload) = line.strip_suffix(b"\n") else {
			return Err(());
		};

		if payload.is_empty() || payload.len() > limit || payload.contains(&b'\r') {
			return Err(());
		}

		std::str::from_utf8(payload).map_err(|_| ())?;

		frames.push(payload.to_vec());
	}

	Ok(frames)
}

proptest! {
	#[test]
	fn incremental_codec_matches_independent_reference(
		payloads in prop::collection::vec("[ -~]{1,128}", 1..8),
		chunks in prop::collection::vec(1usize..64, 1..64),
	) {
		let mut bytes = Vec::new();

		for payload in &payloads {
			bytes.extend_from_slice(payload.as_bytes());
			bytes.push(b'\n');
		}

		let expected = reference_decode(&bytes, 4096).unwrap();
		let mut decoder = FrameDecoder::new(4096).unwrap();
		let mut actual = Vec::new();

		let mut cursor = 0;

		for chunk in chunks {
			let end = (cursor + chunk).min(bytes.len());
			let piece = bytes.get(cursor..end).expect("cursor <= end <= len by construction");
			actual.extend(decoder.push(piece).unwrap());
			cursor = end;

			if cursor == bytes.len() { break; }
		}

		if cursor != bytes.len() {
			let rest = bytes.get(cursor..).expect("cursor <= len by construction");
			actual.extend(decoder.push(rest).unwrap());
		}

		decoder.finish_eof().unwrap();
		let actual = actual.into_iter().map(|value| value.to_vec()).collect::<Vec<_>>();
		prop_assert_eq!(actual, expected);
	}
}
