//! v346 (S59 Thu, DP 2026-10-15 17:13 — "if there is a way we can provide the user feedback in terms of % loaded for the
//! Black start, please do"): THE RESTORE'S PROGRESS. A node rebuilt from this device's saved channel state (the Offline
//! room, the online boot) decrypts and reads the channel monitors one by one, then the channel manager — on a phone with
//! many channels, seconds. A sink set here hears each step — the stage, the bytes of saved state read so far, the bytes
//! in all — and is given a pause between steps so the page can paint what it heard (a WASM restore runs on the page's
//! own thread; without the pause the page shows nothing until the end). Nothing is set in native code or in tests: the
//! steps cost nothing and restore runs as before.
//!
//! The stages, in order: "channels" (before each monitor: `done` = the bytes read so far; `total` = every monitor's
//! bytes + the manager's), "manager" (before the channel manager is read), "ready" (the end; `done == total`). The
//! bytes are of the saved state, not of time: the manager's read is heavier per byte than a monitor's, so a page that
//! shows a percentage shows "of the saved state read", which is what it is.
use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

pub trait RestoreProgress {
    fn report(&self, stage: &str, done: u64, total: u64);
    /// A chance for the page to paint before the next step; a native sink answers at once.
    fn pause(&self) -> Pin<Box<dyn Future<Output = ()> + '_>>;
}

thread_local! {
    static SINK: RefCell<Option<Rc<dyn RestoreProgress>>> = const { RefCell::new(None) };
}

/// Set (or clear) the sink the next restore reports to. Per thread; the page's engine has one.
pub fn set_sink(sink: Option<Rc<dyn RestoreProgress>>) {
    SINK.with(|c| *c.borrow_mut() = sink);
}

fn sink() -> Option<Rc<dyn RestoreProgress>> {
    SINK.with(|c| c.borrow().clone())
}

/// One step of a restore: reported to the sink, then its pause. No sink: nothing.
pub async fn step(stage: &str, done: u64, total: u64) {
    if let Some(s) = sink() {
        s.report(stage, done, total);
        s.pause().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tape(RefCell<Vec<(String, u64, u64)>>);
    impl RestoreProgress for Tape {
        fn report(&self, stage: &str, done: u64, total: u64) { self.0.borrow_mut().push((stage.to_string(), done, total)); }
        fn pause(&self) -> Pin<Box<dyn Future<Output = ()> + '_>> { Box::pin(async {}) }
    }

    #[tokio::test]
    async fn v346_steps_reach_the_sink_in_order_and_none_without_one() {
        step("channels", 0, 10).await;   // no sink: nothing happens
        let tape = Rc::new(Tape(RefCell::new(Vec::new())));
        set_sink(Some(tape.clone()));
        step("channels", 0, 10).await;
        step("channels", 4, 10).await;
        step("manager", 7, 10).await;
        step("ready", 10, 10).await;
        set_sink(None);
        step("channels", 0, 10).await;   // cleared: nothing again
        let got = tape.0.borrow().clone();
        assert_eq!(got, vec![
            ("channels".to_string(), 0, 10), ("channels".to_string(), 4, 10), ("manager".to_string(), 7, 10), ("ready".to_string(), 10, 10),
        ]);
    }
}
