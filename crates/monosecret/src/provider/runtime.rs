/// Writes `data` to a spawned child's piped stdin without letting an
/// early-exiting child kill the process.
///
/// The CLI restores SIGPIPE's default disposition (see `bin/monosecret.rs`),
/// so a plain write to a child that already exited — `op item get` rejecting
/// a batch outright without draining stdin, for instance — would terminate
/// monosecret with SIGPIPE instead of surfacing the child's exit status and
/// stderr. The write runs with SIGPIPE blocked on this thread (the process
/// disposition stays untouched so sibling batch threads are unaffected) and
/// a broken pipe is treated as the child's verdict: the caller's
/// `wait_with_output` reports it.
pub(crate) fn write_child_stdin(
	stdin: std::process::ChildStdin,
	data: &str,
) -> std::io::Result<()> {
	#[cfg(unix)]
	let written = {
		let mut blocked: libc::sigset_t = unsafe { std::mem::zeroed() };
		let mut previous: libc::sigset_t = unsafe { std::mem::zeroed() };
		unsafe {
			libc::sigaddset(&raw mut blocked, libc::SIGPIPE);
			libc::pthread_sigmask(libc::SIG_BLOCK, &raw const blocked, &raw mut previous);
		}
		let written = write_stdin_and_close(stdin, data);
		unsafe {
			// Consume a SIGPIPE raised during the write so restoring the
			// mask cannot deliver it. `sigwait` only runs when the signal
			// is pending, so it cannot block.
			let mut pending: libc::sigset_t = std::mem::zeroed();
			libc::sigpending(&raw mut pending);
			if libc::sigismember(&raw const pending, libc::SIGPIPE) == 1 {
				let mut delivered: libc::c_int = 0;
				libc::sigwait(&raw const blocked, &raw mut delivered);
			}
			libc::pthread_sigmask(libc::SIG_SETMASK, &raw const previous, std::ptr::null_mut());
		}
		written
	};
	#[cfg(not(unix))]
	let written = write_stdin_and_close(stdin, data);

	match written {
		Ok(()) => Ok(()),
		// The child exited before the write (or partway through it); its
		// exit status and stderr are the authoritative result.
		Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
		Err(error) => Err(error),
	}
}

fn write_stdin_and_close(mut stdin: std::process::ChildStdin, data: &str) -> std::io::Result<()> {
	use std::io::Write;

	let written = stdin.write_all(data.as_bytes());
	drop(stdin);
	written
}

/// Executes an async future in a blocking context.
///
/// If already inside a tokio runtime, uses `block_in_place` with the
/// existing runtime handle. Otherwise, creates a new runtime.
#[allow(dead_code)]
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
	match tokio::runtime::Handle::try_current() {
		Ok(handle) => tokio::task::block_in_place(|| handle.block_on(future)),
		Err(_) => {
			tokio::runtime::Builder::new_current_thread()
				.enable_all()
				.build()
				.expect("Failed to create tokio runtime")
				.block_on(future)
		}
	}
}
