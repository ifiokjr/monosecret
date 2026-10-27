//! Process-level protections for the window the CLI holds secret values in
//! memory.

/// Disables core dumps on every Unix, and on Linux additionally marks the
/// process non-dumpable so same-user processes cannot attach to its memory or
/// read `/proc/<pid>` files such as `environ` while secrets are loaded.
///
/// The library embedding path (FFI and the language SDKs) deliberately does
/// not call this: the dumpability of a host application's process belongs to
/// that application. Set `MONOSECRET_ALLOW_DUMPABLE=1` to keep the process
/// debuggable while working on monosecret itself; the flag changes nothing
/// about how secrets are stored or transmitted.
pub(crate) fn harden() {
	let allowed = std::env::var_os("MONOSECRET_ALLOW_DUMPABLE").is_some_and(|value| value == "1");
	harden_with(!allowed);
}

/// The callable core of [`harden`], separated so the tests can exercise both
/// arms without mutating process-global environment variables.
pub(crate) fn harden_with(apply: bool) {
	#[cfg(unix)]
	if apply {
		drop_core_limit();
	}

	#[cfg(target_os = "linux")]
	if apply {
		set_non_dumpable();
	}

	#[cfg(not(unix))]
	let _ = apply;
}

/// Sets the soft core limit to zero, leaving the hard limit untouched. A
/// failure leaves the existing limit in place, which is the status quo.
#[cfg(unix)]
fn drop_core_limit() {
	// SAFETY: getrlimit and setrlimit with a pointer to a valid rlimit
	// structure.
	unsafe {
		let mut limit: libc::rlimit = std::mem::zeroed();
		if libc::getrlimit(libc::RLIMIT_CORE, std::ptr::addr_of_mut!(limit)) == 0 {
			limit.rlim_cur = 0;
			libc::setrlimit(libc::RLIMIT_CORE, std::ptr::addr_of!(limit));
		}
	}
}

/// Makes `/proc/<pid>` files owned by root, blocking same-user reads of the
/// process memory and environment. A failure keeps the default dumpability,
/// which is the status quo.
#[cfg(target_os = "linux")]
fn set_non_dumpable() {
	// SAFETY: PR_SET_DUMPABLE with the known argument values.
	unsafe {
		libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
	}
}

#[cfg(test)]
mod tests {
	use super::harden_with;

	#[cfg(unix)]
	fn rlimit_parts() -> (u64, u64) {
		// SAFETY: getrlimit with a pointer to a valid rlimit structure.
		unsafe {
			let mut limit: libc::rlimit = std::mem::zeroed();
			assert_eq!(
				libc::getrlimit(libc::RLIMIT_CORE, std::ptr::addr_of_mut!(limit)),
				0
			);
			(limit.rlim_cur, limit.rlim_max)
		}
	}

	/// Pins the soft limit to the hard maximum, so the assertions below cannot
	/// pass vacuously on a runner whose soft limit already is zero. Both calls
	/// run inside one test because the core limit belongs to the whole test
	/// process and parallel tests would race each other's arrangements.
	#[cfg(unix)]
	#[test]
	fn core_limit_follows_the_hardening_flag() {
		// SAFETY: setrlimit with a pointer to a valid rlimit structure; only
		// ever lowers or holds the soft limit at the hard maximum.
		unsafe {
			let (_, hard) = rlimit_parts();
			let limit = libc::rlimit {
				rlim_cur: hard,
				rlim_max: hard,
			};
			assert_eq!(
				libc::setrlimit(libc::RLIMIT_CORE, std::ptr::addr_of!(limit)),
				0
			);
		}
		harden_with(false);
		let (_, hard) = rlimit_parts();
		assert_eq!(
			rlimit_parts().0,
			hard,
			"opting out must not touch the limit"
		);

		// SAFETY: as above.
		unsafe {
			let limit = libc::rlimit {
				rlim_cur: hard,
				rlim_max: hard,
			};
			assert_eq!(
				libc::setrlimit(libc::RLIMIT_CORE, std::ptr::addr_of!(limit)),
				0
			);
		}
		harden_with(true);
		assert_eq!(rlimit_parts().0, 0, "hardening must clear the soft limit");
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn linux_marks_the_process_non_dumpable() {
		// SAFETY: PR_SET_DUMPABLE and PR_GET_DUMPABLE with known argument
		// values; arranging a known dumpable state first keeps the assertion
		// independent of the harness's own environment.
		unsafe {
			libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
			harden_with(true);
			assert_eq!(libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0), 0);
		}
	}
}
