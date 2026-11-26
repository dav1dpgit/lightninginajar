//! wait.rs — v385 (S72, DP 2026-11-24 16:23 "Go ahead and fix the engine at v385"): every wait in the engine goes
//! through `sleep_ms`, and `sleep_ms` asks the browser's own timer (`setTimeout`) for exactly that wait.
//!
//! WHY. Until v384 the engine's waits were `wasm_timer::Delay`. That library keeps one list of all waits and serves it
//! from its own chain of browser timers (wasm-timer 0.2.5, src/timer/global/wasm.rs). Two lines of that file can leave a
//! wait unserved for seconds:
//!   - `if Arc::strong_count(&timer) > 20 { return; }` — a chain link that finds more than 20 handles on the list ends
//!     without setting the next browser timer;
//!   - `.unwrap_or(Duration::from_secs(5))` — a chain link that finds the list empty sleeps five seconds, and a wait
//!     added in that time is served only by the wake-up of the task that made it.
//! The send's own waits are short (100 ms between looks at a payment's fate, 50 ms on the HTLC watch, the request
//! limits inside the Lightning connection). In the field (2026-11-24, 16:06) a Lightning send that the provider's LND
//! settled 3.98 s after Send was shown paid 9.78 s after Send; in the test browser an 8,000-ms wait took 10,237 ms
//! once in six runs. The library's state on the phone was not seen — the repair does not depend on it: with one
//! browser timer per wait there is no shared list and no chain to end.
//!
//! WHAT IT IS. One `setTimeout(resolve, ms)` behind one `Promise`, taken from the global object, so it is the same
//! on a page and in a worker. Where there is no `setTimeout` at all (not a browser), the old `Delay` is used, so a
//! wait is never shorter than asked: a wait that returned at once would turn every look-again loop into a loop that
//! never lets the page work.
//!
//! WHAT IT IS NOT. No timing was changed: every place waits the same number of milliseconds as before.

/// Wait `ms` milliseconds on the browser's own timer. `0` gives the page one turn (the browser's task queue).
#[cfg(target_arch = "wasm32")]
pub async fn sleep_ms(ms: u32) {
    use wasm_bindgen::{JsCast, JsValue};
    let mut armed = false;
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        let global = js_sys::global();
        if let Ok(f) = js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout")) {
            if let Some(f) = f.dyn_ref::<js_sys::Function>() {
                armed = f.call2(&global, &resolve, &JsValue::from_f64(ms as f64)).is_ok();
            }
        }
    });
    if armed {
        let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
    } else {
        let _ = wasm_timer::Delay::new(std::time::Duration::from_millis(ms as u64)).await;
    }
}

/// Native builds (the tests) have no browser and no waits of their own to serve: nothing in the tested code waits.
#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep_ms(_ms: u32) {}

/// The longest wait `setTimeout` takes as written is 2^31-1 ms; every wait in the engine is far below it. A caller
/// with seconds in hand uses this so the multiplication cannot wrap.
pub fn secs_to_ms(secs: u64) -> u32 {
    secs.saturating_mul(1000).min(i32::MAX as u64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_become_milliseconds_and_never_wrap() {
        assert_eq!(secs_to_ms(0), 0);
        assert_eq!(secs_to_ms(8), 8_000);
        assert_eq!(secs_to_ms(120), 120_000);
        assert_eq!(secs_to_ms(u64::MAX), i32::MAX as u32);
    }
}
