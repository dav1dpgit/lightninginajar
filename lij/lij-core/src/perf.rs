//! v379 (S71, DP 2026-11-19 22:08 "go on the finer report"): THE ENGINE'S OWN RECORD OF TIME — a diagnostic, it changes
//! nothing the wallet does.
//!
//! The page's Performance report could say that the browser's thread was held for 1.6 s while an engine call was
//! pending; it could not say WHICH code held it, nor where the seconds of a Lightning send went. Two records answer
//! that, both read by the page through one call (`report_json`):
//!
//! 1. LONG STRETCHES. The engine's async work runs on the browser's one thread in goes: a future is polled, runs
//!    until it has to wait, and hands the thread back. `timed(name, future)` wraps a future and measures every go.
//!    A go of `LONG_MS` or more is written down with the call's name and the STEP it was in (`step("…")`, a label
//!    the code sets as it moves on; kept per future across its waits). Nothing is written for a short go.
//! 2. EACH SEND'S TIMELINE. `send_mark(hash, what)` writes one line with the clock time for a payment hash:
//!    called, the provider asked and answering, the payment handed to the channel, taken by the provider, the
//!    provider's answer, the outcome. The last `SENDS` sends are kept, 8 characters of the hash each.
//!
//! Cost: two clock reads per go; one small record per mark. Both records live in memory only and die with the page.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// One go of this many ms or more is written down.
pub const LONG_MS: f64 = 50.0;
const STRETCHES: usize = 160;
const SENDS: usize = 20;
const MARKS_PER_SEND: usize = 40;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Stretch {
    /// Clock time (ms since 1970) when the stretch ENDED.
    pub at: f64,
    pub ms: u32,
    pub call: &'static str,
    pub step: &'static str,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SendLine {
    pub hash8: String,
    /// (what, clock ms), in the order they happened.
    pub marks: Vec<(String, f64)>,
}

#[derive(Default)]
struct Rec {
    ring: VecDeque<Stretch>,
    sends: VecDeque<SendLine>,
    counts: std::collections::BTreeMap<&'static str, u64>,
    depth: u32,
    call: &'static str,
    step: &'static str,
    since: f64,
    wrote: bool,
}

thread_local! { static REC: RefCell<Rec> = RefCell::new(Rec::default()); }

fn now() -> f64 { crate::tier2_sync::now_ms() }

fn push(r: &mut Rec, at: f64, ms: f64, call: &'static str, step: &'static str) {
    if r.ring.len() >= STRETCHES { r.ring.pop_front(); }
    r.ring.push_back(Stretch { at, ms: ms.round().max(0.0) as u32, call, step });
    r.wrote = true;
}

/// The code inside a timed future says where it is now. The stretch spent in the step before this one is written down
/// if it was long. Outside a timed future this does nothing.
pub fn step(name: &'static str) {
    let t = now();
    REC.with(|c| {
        let mut r = c.borrow_mut();
        if r.depth == 0 { return; }
        let (dt, call, prev) = (t - r.since, r.call, r.step);
        if dt >= LONG_MS { push(&mut r, t, dt, call, prev); }
        r.step = name;
        r.since = t;
    });
}

/// A label for the length of one piece of code: the step before it comes back when the piece ends.
pub struct StepScope { prev: &'static str }
pub fn step_scope(name: &'static str) -> StepScope {
    let prev = REC.with(|c| c.borrow().step);
    step(name);
    StepScope { prev }
}
impl Drop for StepScope { fn drop(&mut self) { step(self.prev); } }

fn enter(name: &'static str, my_step: &'static str, t0: f64) -> bool {
    REC.with(|c| {
        let mut r = c.borrow_mut();
        r.depth += 1;
        if r.depth == 1 { r.call = name; r.step = my_step; r.since = t0; r.wrote = false; true } else { false }
    })
}
/// The go ends: its last step's stretch is written if long. Answers the step the go ended in (the outermost only).
fn exit(outer: bool, t0: f64) -> Option<&'static str> {
    let t1 = now();
    REC.with(|c| {
        let mut r = c.borrow_mut();
        r.depth = r.depth.saturating_sub(1);
        if !outer { return None; }
        let (dt, call, st) = (t1 - r.since, r.call, r.step);
        if dt >= LONG_MS { push(&mut r, t1, dt, call, st); }
        else if !r.wrote && t1 - t0 >= LONG_MS { push(&mut r, t1, t1 - t0, call, "(several short steps)"); }
        Some(st)
    })
}

/// One piece of code that runs to its end without waiting (a message from the provider, the one-second tick):
/// measured from here to the end of the value's life, like one go of a timed future.
pub struct Scope { outer: bool, t0: f64 }
pub fn scope(name: &'static str) -> Scope { let t0 = now(); Scope { outer: enter(name, "", t0), t0 } }
impl Drop for Scope { fn drop(&mut self) { let _ = exit(self.outer, self.t0); } }

/// Something that happened, counted (a frame from the provider dropped because the wallet was busy).
pub fn count(what: &'static str) { REC.with(|c| { *c.borrow_mut().counts.entry(what).or_insert(0) += 1; }); }

/// Background work started with its goes measured (wasm only: the browser runs it).
#[cfg(target_arch = "wasm32")]
pub fn spawn<F: Future<Output = ()> + 'static>(name: &'static str, fut: F) { wasm_bindgen_futures::spawn_local(timed(name, fut)); }

/// A future whose every go is measured (see the module's text).
pub struct Timed<F> { name: &'static str, step: &'static str, inner: Pin<Box<F>> }

pub fn timed<F: Future>(name: &'static str, inner: F) -> Timed<F> { Timed { name, step: "", inner: Box::pin(inner) } }

impl<F: Future> Future for Timed<F> {
    type Output = F::Output;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let t0 = now();
        // only the outermost timed future of a go keeps the books (a timed future awaited inside another is its part)
        let outer = enter(self.name, self.step, t0);
        let out = self.inner.as_mut().poll(cx);
        let kept = exit(outer, t0);
        if let Some(st) = kept { self.step = st; }
        out
    }
}

/// One line of a send's timeline. `hash_hex` may be the whole payment hash; 8 characters are kept.
pub fn send_mark(hash_hex: &str, what: &str) {
    if hash_hex.is_empty() { return; }
    let h8: String = hash_hex.chars().take(8).collect();
    let t = now();
    REC.with(|c| {
        let mut r = c.borrow_mut();
        if let Some(s) = r.sends.iter_mut().rev().find(|s| s.hash8 == h8) {
            if s.marks.len() < MARKS_PER_SEND { s.marks.push((what.to_string(), t)); }
            return;
        }
        if r.sends.len() >= SENDS { r.sends.pop_front(); }
        r.sends.push_back(SendLine { hash8: h8, marks: vec![(what.to_string(), t)] });
    });
}

/// Has this send's timeline a line that starts with `prefix`? (The watcher of an HTLC stops once the outcome is in.)
pub fn send_has(hash_hex: &str, prefix: &str) -> bool {
    let h8: String = hash_hex.chars().take(8).collect();
    REC.with(|c| c.borrow().sends.iter().rev().find(|s| s.hash8 == h8).map(|s| s.marks.iter().any(|(w, _)| w.starts_with(prefix))).unwrap_or(false))
}

/// The records as JSON: {"long_ms":50,"stretches":[{at,ms,call,step}],"sends":[{hash8,marks:[[what,at]]}],"counts":{what:n}}.
pub fn report_json() -> String {
    REC.with(|c| {
        let r = c.borrow();
        serde_json::json!({
            "long_ms": LONG_MS,
            "stretches": r.ring.iter().collect::<Vec<_>>(),
            "sends": r.sends.iter().collect::<Vec<_>>(),
            "counts": r.counts,
        }).to_string()
    })
}

/// Both records emptied (the page's "start a fresh report").
pub fn clear() { REC.with(|c| { let mut r = c.borrow_mut(); r.ring.clear(); r.sends.clear(); r.counts.clear(); }); }

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct NoWake;
    impl Wake for NoWake { fn wake(self: Arc<Self>) {} }
    fn poll_once<F: Future + Unpin>(f: &mut F) -> Poll<F::Output> {
        let w = Waker::from(Arc::new(NoWake));
        Pin::new(f).poll(&mut Context::from_waker(&w))
    }
    fn busy(ms: u64) { std::thread::sleep(std::time::Duration::from_millis(ms)); }
    /// A future that is pending once, then ready.
    struct Twice(bool);
    impl Future for Twice {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> { if self.0 { Poll::Ready(()) } else { self.0 = true; Poll::Pending } }
    }

    #[test]
    fn s71_a_long_go_is_written_with_its_call_and_step_and_a_short_one_is_not() {
        clear();
        let mut f = timed("the_call", async {
            step("first");
            busy(70);
            step("second");
            busy(5);
            Twice(false).await;
            busy(80);
        });
        assert!(poll_once(&mut f).is_pending());
        let j: serde_json::Value = serde_json::from_str(&report_json()).unwrap();
        let s = j["stretches"].as_array().unwrap();
        assert_eq!(s.len(), 1, "one long stretch so far (the 5 ms after it is short): {j}");
        assert_eq!(s[0]["call"], "the_call"); assert_eq!(s[0]["step"], "first");
        assert!(s[0]["ms"].as_u64().unwrap() >= 60);
        // the second go: the step set before the wait is still the future's step
        assert!(poll_once(&mut f).is_ready());
        let j: serde_json::Value = serde_json::from_str(&report_json()).unwrap();
        let s = j["stretches"].as_array().unwrap();
        assert_eq!(s.len(), 2, "{j}");
        assert_eq!(s[1]["step"], "second", "a future keeps its step across a wait");
        assert!(s[1]["ms"].as_u64().unwrap() >= 70 && s[1]["at"].as_f64().unwrap() >= s[0]["at"].as_f64().unwrap());
    }

    #[test]
    fn s71_many_short_steps_in_one_long_go_are_written_as_one_line() {
        clear();
        let mut f = timed("walk", async { for _ in 0..6 { step("a"); busy(12); step("b"); busy(12); } });
        assert!(poll_once(&mut f).is_ready());
        let j: serde_json::Value = serde_json::from_str(&report_json()).unwrap();
        let s = j["stretches"].as_array().unwrap();
        assert_eq!(s.len(), 1, "{j}");
        assert_eq!(s[0]["step"], "(several short steps)"); assert!(s[0]["ms"].as_u64().unwrap() >= 120);
    }

    #[test]
    fn s71_a_timed_future_inside_another_is_its_part_and_step_outside_does_nothing() {
        clear();
        step("nobody is timed");
        let mut f = timed("outer", async { step("outer work"); timed("inner", async { busy(60); }).await; });
        assert!(poll_once(&mut f).is_ready());
        let j: serde_json::Value = serde_json::from_str(&report_json()).unwrap();
        let s = j["stretches"].as_array().unwrap();
        assert_eq!(s.len(), 1, "{j}");
        assert_eq!(s[0]["call"], "outer"); assert_eq!(s[0]["step"], "outer work");
    }

    #[test]
    fn s71_a_piece_that_runs_to_its_end_is_measured_and_a_step_label_gives_way_when_its_piece_ends() {
        clear();
        {
            let _p = scope("a_message");
            step("read");
            { let _s = step_scope("store"); busy(60); }
            busy(70);   // back in "read"
        }
        { let _p = scope("quick"); busy(2); }
        { let _s = step_scope("outside any piece"); busy(60); }
        count("frames dropped"); count("frames dropped");
        let j: serde_json::Value = serde_json::from_str(&report_json()).unwrap();
        let s = j["stretches"].as_array().unwrap();
        assert_eq!(s.len(), 2, "{j}");
        assert_eq!(s[0]["call"], "a_message"); assert_eq!(s[0]["step"], "store");
        assert_eq!(s[1]["step"], "read");
        assert_eq!(j["counts"]["frames dropped"], 2);
    }

    #[test]
    fn s71_a_sends_timeline_keeps_its_lines_in_order_and_the_ring_keeps_the_last_sends() {
        clear();
        let h = "ab".repeat(32);
        send_mark(&h, "send called"); send_mark(&h, "handed to the channel"); send_mark(&h, "outcome: sent");
        send_mark("", "nothing");
        assert!(send_has(&h, "outcome") && !send_has(&h, "taken") && !send_has("ffffffff", "send"));
        let j: serde_json::Value = serde_json::from_str(&report_json()).unwrap();
        let s = j["sends"].as_array().unwrap();
        assert_eq!(s.len(), 1); assert_eq!(s[0]["hash8"], "abababab");
        let m = s[0]["marks"].as_array().unwrap();
        assert_eq!(m.len(), 3); assert_eq!(m[0][0], "send called"); assert_eq!(m[2][0], "outcome: sent");
        assert!(m[2][1].as_f64().unwrap() >= m[0][1].as_f64().unwrap());
        for i in 0..(SENDS + 3) { send_mark(&format!("{:08x}", i), "send called"); }
        let j: serde_json::Value = serde_json::from_str(&report_json()).unwrap();
        assert_eq!(j["sends"].as_array().unwrap().len(), SENDS);
        assert_eq!(j["long_ms"], 50.0);
        clear();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&report_json()).unwrap()["sends"].as_array().unwrap().len(), 0);
    }
}
