// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! A simple module which either re-exports [`std::time::Instant`] or a mocked version of it for
//! tests.

#[cfg(all(not(test), not(target_arch = "wasm32")))]
pub use std::time::Instant;

// LiJ (re-port): on wasm32 `std::time::Instant::now()` panics ("time not implemented");
// `outbound_payment` keeps a `first_attempted_at` for `Retry::Timeout`, which LiJ never uses
// (Retry::Attempts(0)). A browser-clock Instant satisfies the two calls the crate makes.
#[cfg(all(not(test), target_arch = "wasm32"))]
pub use wasm_instant::Instant;
#[cfg(all(not(test), target_arch = "wasm32"))]
mod wasm_instant {
	use core::time::Duration;
	/// Monotonic-enough time on wasm32: milliseconds from the browser clock.
	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
	pub struct Instant(Duration);
	impl Instant {
		/// Now, per the browser.
		pub fn now() -> Self { Self(Duration::from_millis(js_sys::Date::now() as u64)) }
		/// Time since `earlier` (saturating).
		pub fn duration_since(&self, earlier: Self) -> Duration { self.0.saturating_sub(earlier.0) }
		/// Time since this instant.
		pub fn elapsed(&self) -> Duration { Self::now().duration_since(*self) }
	}
	impl core::ops::Sub<Duration> for Instant {
		type Output = Self;
		fn sub(self, other: Duration) -> Self { Self(self.0.saturating_sub(other)) }
	}
	impl core::ops::Add<Duration> for Instant {
		type Output = Self;
		fn add(self, other: Duration) -> Self { Self(self.0 + other) }
	}
}
#[cfg(test)]
pub use test::Instant;

#[cfg(test)]
mod test {
	use core::cell::Cell;
	use core::ops::Sub;
	use core::time::Duration;

	/// Time that can be advanced manually in tests.
	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
	pub struct Instant(Duration);

	impl Instant {
		thread_local! {
			static ELAPSED: Cell<Duration> = const { Cell::new(Duration::from_secs(0)) };
		}

		pub fn advance(duration: Duration) {
			Self::ELAPSED.with(|elapsed| elapsed.set(elapsed.get() + duration))
		}

		pub fn now() -> Self {
			Self(Self::ELAPSED.with(|elapsed| elapsed.get()))
		}

		pub fn duration_since(&self, earlier: Self) -> Duration {
			self.0 - earlier.0
		}
	}

	impl Sub<Duration> for Instant {
		type Output = Self;

		fn sub(self, other: Duration) -> Self {
			Self(self.0 - other)
		}
	}

	#[test]
	fn time_passes_when_advanced() {
		let now = Instant::now();

		Instant::advance(Duration::from_secs(1));
		Instant::advance(Duration::from_secs(1));

		let later = Instant::now();

		assert_eq!(now.0 + Duration::from_secs(2), later.0);
	}
}

// ── LiJ wasm32 clock shims (re-ported to 0.2.6) ─────────────────────────────────────
// wasm32-unknown-unknown has no wall clock: `std::time::SystemTime::now()` panics with
// "time not implemented on this platform" (2026-09-12: the first v241 tick did exactly
// that and left the engine's lock held). Every wall-clock read in this crate goes through
// these two helpers; on wasm32 they read the browser clock, elsewhere they are std.
/// Wall-clock now.
pub fn lij_now() -> std::time::SystemTime {
	#[cfg(target_arch = "wasm32")]
	{ std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(js_sys::Date::now() as u64) }
	#[cfg(not(target_arch = "wasm32"))]
	{ std::time::SystemTime::now() }
}
/// Time since the Unix epoch (what `SystemTime::UNIX_EPOCH.elapsed()` returns).
pub fn lij_since_epoch() -> Result<std::time::Duration, std::time::SystemTimeError> {
	#[cfg(target_arch = "wasm32")]
	{ Ok(std::time::Duration::from_millis(js_sys::Date::now() as u64)) }
	#[cfg(not(target_arch = "wasm32"))]
	{ std::time::SystemTime::UNIX_EPOCH.elapsed() }
}
