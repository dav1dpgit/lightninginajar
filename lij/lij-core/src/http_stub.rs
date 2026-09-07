// http_stub.rs
//
// Step 6a — placeholder HTTP backend. Always returns "not implemented" errors.
// Replaced by the real WASM fetch implementation in step 8 when send/receive
// needs working network I/O.
//
// Why we have this:
//   The IndependentClient (step 5) requires an Arc<dyn EsploraHttp> at
//   construction time. Step 6a wires IndependentClient into LijNode but
//   the real network code isn't ready until step 8. The stub lets the
//   independent path be constructed and registered with the broadcaster
//   and fee estimator now, while keeping the path's is_available() honest:
//   it will report unavailable because every query fails.
//
// Behavior:
//   - GET / POST: return Err immediately. EsploraEndpoint records a failure.
//   - After MAX_CONSECUTIVE_FAILURES (3), the endpoint demotes itself.
//   - After all endpoints demote, healthy_count() == 0, is_available() == false.
//   - The broadcaster/fee_estimator silently skip the independent path.
//   - This is the correct degraded behavior for "independent path not yet
//     functional" — neither broken nor pretending to work.
//
// Step 8 replacement:
//   Real impl uses web_sys::fetch (WASM) or reqwest (native) and lives in
//   lij-wasm. This stub stays in lij-core for native test convenience.

use std::future::Future;
use std::pin::Pin;

use crate::error::{LijError, LijResult};
use crate::independent::{EsploraHttp, HttpResponse};

type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub struct StubEsploraHttp;

impl StubEsploraHttp {
    pub fn new() -> Self { Self }
}

impl EsploraHttp for StubEsploraHttp {
    fn get<'a>(&'a self, _url: &'a str) -> LocalBoxFuture<'a, LijResult<HttpResponse>> {
        Box::pin(async move {
            Err(LijError::Lsp(
                "stub HTTP backend: real impl wires in step 8".into(),
            ))
        })
    }

    fn post<'a>(
        &'a self,
        _url: &'a str,
        _body: &'a [u8],
        _content_type: &'a str,
    ) -> LocalBoxFuture<'a, LijResult<HttpResponse>> {
        Box::pin(async move {
            Err(LijError::Lsp(
                "stub HTTP backend: real impl wires in step 8".into(),
            ))
        })
    }
}
