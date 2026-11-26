//! inside.rs — v387 (S72, F3b-2 — DP 2026-11-25 09:59 "I do want everything move from the web form as possible in F"):
//! ONE WAY FOR lij-core's OWN PROVIDER REQUESTS TO GO INSIDE THE LIGHTNING CONNECTION.
//!
//! The requests inside the connection are sent by lij-wasm (`lijox_inside`): it owns the wallet's lock, and a request
//! inside the connection needs that lock to be free while it waits. Some of the engine's provider requests live here
//! in lij-core (the channel terms, the buy, the invoice's secret in lsps2.rs; the funding check in jit_funding.rs), and
//! lij-core cannot call lij-wasm. So lij-wasm hands lij-core ONE function when a wallet starts, and those requests
//! ask it first.
//!
//! `ask` answers:
//!   None           no function was handed over, or `endpoint` is not the provider in use, or that provider does not
//!                  serve `method` inside the connection → the caller sends its web request, exactly as before
//!   Some(Ok(a))    the provider answered: `a.ok` for a 2xx, else the web route's status; `a.text` is the body as JSON
//!                  text — what the web request would have read
//!   Some(Err(e))   no answer inside the connection. THE WEB REQUEST IS NOT TRIED (a method a provider serves inside
//!                  the connection is not sent to it as a web request).
//! A caller must not hold the wallet's lock around `ask`.
//!
//! Only the browser build has the function (the engine runs nowhere else); on any other target `ask` answers None.
use crate::error::LijResult;

/// A provider's answer inside the connection, in the terms of the web request it stands for.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer { pub ok: bool, pub status: u16, pub text: String }

/// True when `a` and `b` name the same web address (a trailing slash and the letter case of the host aside).
pub fn same_endpoint(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim().trim_end_matches('/').to_ascii_lowercase();
    let (x, y) = (norm(a), norm(b));
    !x.is_empty() && x == y
}

#[cfg(target_arch = "wasm32")]
mod hook {
    use super::Answer;
    use crate::error::LijResult;
    use std::cell::RefCell;
    use std::future::Future;
    use std::pin::Pin;
    use std::rc::Rc;
    pub type AskFuture = Pin<Box<dyn Future<Output = Option<LijResult<Answer>>>>>;
    /// (endpoint, method, params as JSON text, the longest wait in ms)
    pub type AskFn = Rc<dyn Fn(String, String, String, u64) -> AskFuture>;
    thread_local! { static HOOK: RefCell<Option<AskFn>> = RefCell::new(None); }
    pub fn set(f: AskFn) { HOOK.with(|h| *h.borrow_mut() = Some(f)); }
    pub fn get() -> Option<AskFn> { HOOK.with(|h| h.borrow().clone()) }
}
#[cfg(target_arch = "wasm32")]
pub use hook::{AskFn, AskFuture};

/// lij-wasm hands over the function when a wallet starts (the newest wallet's function is the one kept).
#[cfg(target_arch = "wasm32")]
pub fn set_hook(f: AskFn) { hook::set(f); }

#[cfg(target_arch = "wasm32")]
pub async fn ask(endpoint: &str, method: &str, params_json: String, timeout_ms: u64) -> Option<LijResult<Answer>> {
    let f = hook::get()?;
    f(endpoint.to_string(), method.to_string(), params_json, timeout_ms).await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn ask(_endpoint: &str, _method: &str, _params_json: String, _timeout_ms: u64) -> Option<LijResult<Answer>> { None }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v387_the_same_web_address_whatever_the_trailing_slash_or_the_case() {
        assert!(same_endpoint("https://lsp1.example/api/", "https://LSP1.example/api"));
        assert!(same_endpoint(" https://lsp1.example ", "https://lsp1.example/"));
        assert!(!same_endpoint("https://lsp1.example", "https://lsp2.example"));
        assert!(!same_endpoint("https://lsp1.example/api", "https://lsp1.example"));
        assert!(!same_endpoint("", ""));
    }
    #[test]
    fn v387_outside_the_browser_nothing_is_asked_inside_the_connection() {
        let mut fut = Box::pin(ask("https://lsp1.example", "lijox.jit_info", "{}".into(), 1000));
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        match std::future::Future::poll(fut.as_mut(), &mut cx) { std::task::Poll::Ready(r) => assert!(r.is_none()), _ => panic!("ask must answer at once outside the browser") }
    }
}
