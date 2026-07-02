// server: work-stealing scheduler test (Axum + multi-thread Tokio runtime).
//
// actix-web (#[actix_web::main]) gives each worker its own current-thread
// Tokio runtime, so tokio::spawn never crosses thread boundaries — OBI's TID
// fallback coincidentally works there.
//
// Axum with #[tokio::main] uses a SINGLE multi-thread work-stealing runtime.
// tokio::spawn enqueues tasks in the global scheduler; any worker thread can
// dequeue and run them. OBI MUST use the tokio_task_state ancestry walk to
// propagate context; TID-based lookup alone will fail.
//
// Start backend first:  cargo run -p backend
// Then:                  cargo run -p server
//
// Test with:
//   curl http://localhost:8092/health
//   curl http://localhost:8092/ws-direct    # handler on whichever worker owns it
//   curl http://localhost:8092/ws-spawn     # child task may land on a different worker
//   curl http://localhost:8092/ws-nested    # two spawn levels; each may migrate

use axum::{Router, routing::get, http::StatusCode, response::IntoResponse};

const BACKEND: &str = "http://127.0.0.1:8093/ping";

async fn call_backend(label: &str) -> Result<String, String> {
    call_backend_url(label, BACKEND).await
}

// Async backend call to an explicit URL — used by the async A/B discrimination
// endpoints (/ws-spawn-a -> /ping-c, /ws-spawn-b -> /ping-d).
async fn call_backend_url(label: &str, url: &str) -> Result<String, String> {
    reqwest::get(url)
        .await
        .map_err(|e| format!("[{}] connect error: {}", label, e))?
        .text()
        .await
        .map_err(|e| format!("[{}] read error: {}", label, e))
}

fn respond(result: Result<String, String>) -> impl IntoResponse {
    match result {
        Ok(body) => (StatusCode::OK, body),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

// /ws-direct — handler awaits reqwest directly.
// The handler task itself can land on any worker thread (no spawn involved).
async fn ws_direct() -> impl IntoResponse {
    println!(
        "[ws-direct] thread={:?}",
        std::thread::current().id()
    );
    respond(call_backend("ws-direct").await)
}

// /ws-spawn — one level of tokio::spawn between the handler and the outgoing call.
// The spawned task is enqueued globally and may be stolen by a different worker.
// If it migrates: tokio_thread_state[new_tid].current_task != handler task, so
// TID-based context lookup returns nothing. OBI must walk tokio_task_state ancestry.
async fn ws_spawn() -> impl IntoResponse {
    let handler_tid = std::thread::current().id();
    println!("[ws-spawn] handler thread={:?}", handler_tid);

    let handle = tokio::spawn(async move {
        // Yield once before doing any work: this pops the task out of the worker's
        // LIFO slot and puts it on the run queue, so an idle worker can steal it.
        // Without this, under -c saturation Tokio runs the freshly spawned task on
        // its spawning worker (migrated=false) and the cross-thread walk is never
        // exercised. With it, child_tid (read after the yield) reflects the worker
        // that actually resumed the task — frequently a different one under load.
        tokio::task::yield_now().await;
        let child_tid = std::thread::current().id();
        let migrated = child_tid != handler_tid;
        println!(
            "[ws-spawn] child thread={:?} migrated={}",
            child_tid, migrated
        );
        call_backend("ws-spawn").await
    });

    respond(handle.await.unwrap_or_else(|e| Err(e.to_string())))
}

// Distinct backend paths for the async A/B discriminator, kept separate from the
// spawn_blocking A/B paths (/ping-a, /ping-b) so the two discrimination subtests
// never cross-classify each other's traces.
const BACKEND_C: &str = "http://127.0.0.1:8093/ping-c";
const BACKEND_D: &str = "http://127.0.0.1:8093/ping-d";

// /ws-spawn-a and /ws-spawn-b — the ASYNC work-stealing discriminator. Same shape
// as /ws-spawn (tokio::spawn + yield_now to force the child onto the run queue so
// an idle worker can steal it under concurrent load), but each calls a DISTINCT
// backend path. Under migration the spawned task egresses on a worker that never
// handled the inbound request; only the tokio_task_state ancestry walk can attribute
// it. Non-migrated requests still resolve via the generic thread=request path, so —
// unlike spawn_blocking — the probes-off baseline is not ~0; the two subtests are
// calibrated from measured on/off numbers rather than a shared fixed threshold.
async fn ws_spawn_a() -> impl IntoResponse {
    let handler_tid = std::thread::current().id();
    let handle = tokio::spawn(async move {
        tokio::task::yield_now().await;
        let child_tid = std::thread::current().id();
        // Prints migrated=true when the child resumed on a different worker than the
        // handler — confirms work-stealing actually occurred so the discrimination
        // numbers can be interpreted (a low gap with migrated=false everywhere would
        // just mean nothing migrated).
        println!("[ws-spawn-a] child={:?} migrated={}", child_tid, child_tid != handler_tid);
        call_backend_url("ws-spawn-a", BACKEND_C).await
    });
    respond(handle.await.unwrap_or_else(|e| Err(e.to_string())))
}

async fn ws_spawn_b() -> impl IntoResponse {
    let handler_tid = std::thread::current().id();
    let handle = tokio::spawn(async move {
        tokio::task::yield_now().await;
        let child_tid = std::thread::current().id();
        println!("[ws-spawn-b] child={:?} migrated={}", child_tid, child_tid != handler_tid);
        call_backend_url("ws-spawn-b", BACKEND_D).await
    });
    respond(handle.await.unwrap_or_else(|e| Err(e.to_string())))
}

// /ws-nested — two levels of tokio::spawn before the outgoing call.
// Each spawn is a new entry in tokio_task_state; OBI must walk depth-2 ancestry.
async fn ws_nested() -> impl IntoResponse {
    let handler_tid = std::thread::current().id();
    println!("[ws-nested] handler thread={:?}", handler_tid);

    let handle = tokio::spawn(async move {
        // Yield so the outer task can be stolen by another worker (see ws_spawn).
        tokio::task::yield_now().await;
        println!(
            "[ws-nested] outer thread={:?} migrated={}",
            std::thread::current().id(),
            std::thread::current().id() != handler_tid
        );
        let outer_tid = std::thread::current().id();
        let inner = tokio::spawn(async move {
            // Yield again so the inner task can migrate independently of the outer.
            tokio::task::yield_now().await;
            println!(
                "[ws-nested] inner thread={:?} migrated={}",
                std::thread::current().id(),
                std::thread::current().id() != outer_tid
            );
            call_backend("ws-nested").await
        });
        inner.await.unwrap_or_else(|e| Err(e.to_string()))
    });

    respond(handle.await.unwrap_or_else(|e| Err(e.to_string())))
}

// Synchronous backend call for use inside spawn_blocking. ureq makes a direct TCP
// connection with no Tokio dependency (reqwest::blocking would panic here).
fn call_backend_blocking() -> Result<String, String> {
    ureq::get(BACKEND)
        .call()
        .map_err(|e| e.to_string())
        .and_then(|r| r.into_string().map_err(|e| e.to_string()))
}

// /blocking — handler dispatches the outgoing call onto the blocking pool via
// spawn_blocking. The ureq call runs on a dedicated blocking-pool OS thread, not
// an async worker — OBI must bridge the inbound conn across that boundary.
async fn blocking() -> impl IntoResponse {
    println!("[blocking] handler on async thread {:?}", std::thread::current().id());
    let result = tokio::task::spawn_blocking(|| {
        println!("[blocking] executing on blocking thread {:?}", std::thread::current().id());
        call_backend_blocking()
    })
    .await
    .unwrap_or_else(|e| Err(e.to_string()));
    respond(result)
}

// Same as call_backend_blocking but to an explicit URL — used by the A/B
// probe-discrimination endpoints (/blocking-a -> /ping-a, /blocking-b -> /ping-b).
fn call_backend_blocking_url(url: &str) -> Result<String, String> {
    ureq::get(url)
        .call()
        .map_err(|e| e.to_string())
        .and_then(|r| r.into_string().map_err(|e| e.to_string()))
}

const BACKEND_A: &str = "http://127.0.0.1:8093/ping-a";
const BACKEND_B: &str = "http://127.0.0.1:8093/ping-b";

// /blocking-a and /blocking-b are the probe-discrimination endpoints. Each
// dispatches a spawn_blocking closure that calls a DISTINCT backend path.
// spawn_blocking always runs on a blocking-pool thread that never handled the
// inbound request, so the generic thread=request assumption cannot correlate it —
// under concurrent A/B load the generic process-level fallback (last-write-wins)
// misattributes, producing traces where a /blocking-a server span contains a
// /ping-b backend span (or vice versa). The Tokio bridge attributes per task
// identity, so cross-contamination stays low. The integration test asserts that
// each side produces at least `minClean` cleanly-attributed chains (not that
// contamination is zero — a small keep-alive tail is tolerated); that clean-chain
// floor collapses with the Tokio probes detached and is met with them attached
// (when they actually fire — debug always; release after the raw::poll re-target).
async fn blocking_a() -> impl IntoResponse {
    let result = tokio::task::spawn_blocking(|| call_backend_blocking_url(BACKEND_A))
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
    respond(result)
}

async fn blocking_b() -> impl IntoResponse {
    let result = tokio::task::spawn_blocking(|| call_backend_blocking_url(BACKEND_B))
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
    respond(result)
}

// /blocking-nested — async spawn -> spawn_blocking -> ureq. Adds a level of async
// task ancestry before the blocking boundary.
async fn blocking_nested() -> impl IntoResponse {
    println!("[blocking-nested] handler on {:?}", std::thread::current().id());
    let handle = tokio::spawn(async move {
        tokio::task::yield_now().await;
        tokio::task::spawn_blocking(|| {
            println!("[blocking-nested] blocking thread {:?}", std::thread::current().id());
            call_backend_blocking()
        })
        .await
        .unwrap_or_else(|e| Err(e.to_string()))
    });
    respond(handle.await.unwrap_or_else(|e| Err(e.to_string())))
}

async fn health() -> impl IntoResponse {
    "ok\n"
}

// Four worker threads makes stealing likely under concurrent load.
// Run `hey -n 100 -c 10 http://localhost:8092/ws-spawn` to force migrations.
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let app = Router::new()
        .route("/health", get(health))
        .route("/ws-direct", get(ws_direct))
        .route("/ws-spawn", get(ws_spawn))
        .route("/ws-nested", get(ws_nested))
        .route("/blocking", get(blocking))
        .route("/blocking-nested", get(blocking_nested))
        .route("/blocking-a", get(blocking_a))
        .route("/blocking-b", get(blocking_b))
        .route("/ws-spawn-a", get(ws_spawn_a))
        .route("/ws-spawn-b", get(ws_spawn_b));

    println!("server (work-stealing) listening on http://0.0.0.0:8092");
    println!("  backend expected at http://127.0.0.1:8093/ping");
    println!("  GET /health          — liveness check");
    println!("  GET /ws-direct       — handler calls backend; no spawn");
    println!("  GET /ws-spawn        — one tokio::spawn; child may migrate thread");
    println!("  GET /ws-nested       — two nested spawns; each may migrate");
    println!("  GET /blocking        — spawn_blocking -> ureq (blocking pool)");
    println!("  GET /blocking-nested — spawn -> spawn_blocking -> ureq");
    println!("  GET /blocking-a      — spawn_blocking -> ureq /ping-a (blocking discrimination A)");
    println!("  GET /blocking-b      — spawn_blocking -> ureq /ping-b (blocking discrimination B)");
    println!("  GET /ws-spawn-a      — tokio::spawn -> reqwest /ping-c (async discrimination A)");
    println!("  GET /ws-spawn-b      — tokio::spawn -> reqwest /ping-d (async discrimination B)");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8092")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
