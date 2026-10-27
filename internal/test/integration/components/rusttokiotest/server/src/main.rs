// server: Axum on a single multi-thread work-stealing Tokio runtime (#[tokio::main]).
// tokio::spawn enqueues the task on the shared scheduler and any worker may run it, so
// an egress can run on a thread that never handled the inbound request; OBI attributes
// it by task lineage, not by thread. (actix-web is the other common shape: one
// current-thread runtime per worker, where tasks never migrate.)
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
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
// Every B side also targets port 8094, so the sides differ at the transport level
// (orig_dport) as well as by HTTP path.
const BACKEND_D: &str = "http://127.0.0.1:8094/ping-d";

// /ws-spawn-a and /ws-spawn-b: the async work-stealing discriminator. Same shape as
// /ws-spawn (tokio::spawn + yield_now, so an idle worker can steal the child under
// concurrent load), but each calls a distinct backend path. Under migration the
// spawned task egresses on a worker that never handled the inbound request; only the
// task lineage walk can attribute it.
async fn ws_spawn_a() -> impl IntoResponse {
    let handler_tid = std::thread::current().id();
    let handle = tokio::spawn(async move {
        tokio::task::yield_now().await;
        let child_tid = std::thread::current().id();
        // migrated=true means the child resumed on a different worker than the handler,
        // so the app log shows whether work-stealing actually happened in a run.
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

// Direct-I/O (Shape B) backend call: the CURRENT task opens its OWN TcpStream and
// performs the write/read itself — there is NO pooled background connection task.
// The egress send syscall therefore happens while this task is being polled, so
// current_task at the write is the (spawned, per-request) task with the inbound-conn
// lineage — unlike reqwest (Shape A), where a decoupled connection task does the write
// on a task that has no link to the request. Fresh connection per call (Connection:
// close) so nothing is pooled/reused.
async fn call_backend_direct(label: &str, addr: &str, path: &str) -> Result<String, String> {
    let mut sock = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("[{}] connect error: {}", label, e))?;
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, addr
    );
    sock.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("[{}] write error: {}", label, e))?;
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf)
        .await
        .map_err(|e| format!("[{}] read error: {}", label, e))?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

// /ws-direct-a and /ws-direct-b — the DIRECT-I/O (Shape B) work-stealing discriminator.
// Same spawn+yield shape as /ws-spawn-a/b so the child can be stolen by another worker,
// but the outbound call is a raw TcpStream write on the child task itself (no reqwest
// connection pool). Distinct backends: A -> :8093/ping-e, B -> :8094/ping-f.
async fn ws_direct_a() -> impl IntoResponse {
    let handler_tid = std::thread::current().id();
    let handle = tokio::spawn(async move {
        tokio::task::yield_now().await;
        let child_tid = std::thread::current().id();
        println!("[ws-direct-a] child={:?} migrated={}", child_tid, child_tid != handler_tid);
        call_backend_direct("ws-direct-a", "127.0.0.1:8093", "/ping-e").await
    });
    respond(handle.await.unwrap_or_else(|e| Err(e.to_string())))
}

async fn ws_direct_b() -> impl IntoResponse {
    let handler_tid = std::thread::current().id();
    let handle = tokio::spawn(async move {
        tokio::task::yield_now().await;
        let child_tid = std::thread::current().id();
        println!("[ws-direct-b] child={:?} migrated={}", child_tid, child_tid != handler_tid);
        call_backend_direct("ws-direct-b", "127.0.0.1:8094", "/ping-f").await
    });
    respond(handle.await.unwrap_or_else(|e| Err(e.to_string())))
}

// Shared, process-wide reqwest client: keep-alive pooling ON. Every call after the
// first REUSES the same hyper connection-driver task — the exact pattern where a
// lineage-based resolution could leak the FIRST request's trace into later requests
// (the pooled-driver-reuse hazard). The id-keyed debug path fail-closes it by deleting
// a task's id entry at dealloc: by the time request N reuses the driver, request 1's
// task ids are dead and the walk misses (orphan) instead of resolving request 1.
static POOL_CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();

fn pool_client() -> &'static reqwest::Client {
    POOL_CLIENT.get_or_init(reqwest::Client::new)
}

async fn call_backend_pooled(label: &str, url: &str) -> Result<String, String> {
    pool_client()
        .get(url)
        .send()
        .await
        .map_err(|e| format!("[{}] connect error: {}", label, e))?
        .text()
        .await
        .map_err(|e| format!("[{}] read error: {}", label, e))
}

const BACKEND_G: &str = "http://127.0.0.1:8093/ping-g";
const BACKEND_H: &str = "http://127.0.0.1:8094/ping-h";

// /ws-pool-a and /ws-pool-b — the SHARED-CLIENT (pool-reuse) A/B discriminator.
// Same spawn+yield shape as /ws-spawn-a/b, but through ONE process-wide reqwest
// client, so concurrent A/B requests interleave on reused keep-alive connections
// and their long-lived driver tasks. The safety contract under test: an egress on a
// REUSED driver must never resolve to a previous request's trace (contaminated==0);
// correlation coverage on reused drivers is allowed to drop (fail-closed orphans).
async fn ws_pool_a() -> impl IntoResponse {
    let handler_tid = std::thread::current().id();
    let handle = tokio::spawn(async move {
        tokio::task::yield_now().await;
        let child_tid = std::thread::current().id();
        println!("[ws-pool-a] child={:?} migrated={}", child_tid, child_tid != handler_tid);
        call_backend_pooled("ws-pool-a", BACKEND_G).await
    });
    respond(handle.await.unwrap_or_else(|e| Err(e.to_string())))
}

async fn ws_pool_b() -> impl IntoResponse {
    let handler_tid = std::thread::current().id();
    let handle = tokio::spawn(async move {
        tokio::task::yield_now().await;
        let child_tid = std::thread::current().id();
        println!("[ws-pool-b] child={:?} migrated={}", child_tid, child_tid != handler_tid);
        call_backend_pooled("ws-pool-b", BACKEND_H).await
    });
    respond(handle.await.unwrap_or_else(|e| Err(e.to_string())))
}

// Channel handoff to ONE long-lived worker task (the actor/queue pattern). The worker
// is spawned lazily on the FIRST request — deliberately the adversarial variant: its
// lineage is parented under that first request's conn task, which stays alive
// (keep-alive) and is re-anchored for every later request on that connection. Without
// the anchor-epoch guard, every later job's egress would resolve whatever request the
// anchor CURRENTLY serves — and since this single worker serves BOTH the A and B
// endpoints, the leak crosses the A/B boundary and shows up as `contaminated` (and as
// `piled` for same-side hits). The safety contract under test: every worker egress
// fails closed (orphan) once its spawn-time epoch is stale; none ever resolves another
// request's trace.
struct ChanJob {
    addr: &'static str,
    path: &'static str,
    reply: tokio::sync::oneshot::Sender<Result<String, String>>,
}

static CHAN_TX: std::sync::OnceLock<tokio::sync::mpsc::UnboundedSender<ChanJob>> =
    std::sync::OnceLock::new();

fn chan_tx() -> &'static tokio::sync::mpsc::UnboundedSender<ChanJob> {
    CHAN_TX.get_or_init(|| {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ChanJob>();
        tokio::spawn(async move {
            println!("[ws-chan] worker started on {:?}", std::thread::current().id());
            while let Some(job) = rx.recv().await {
                // The WORKER does the egress itself (direct TcpStream, Shape B), so the
                // egress task identity is the worker's — never the requesting handler's.
                let res = call_backend_direct("ws-chan-worker", job.addr, job.path).await;
                let _ = job.reply.send(res);
            }
        });
        tx
    })
}

async fn ws_chan(addr: &'static str, path: &'static str) -> Result<String, String> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    chan_tx()
        .send(ChanJob { addr, path, reply: reply_tx })
        .map_err(|_| "worker gone".to_string())?;
    reply_rx
        .await
        .unwrap_or_else(|_| Err("worker dropped reply".to_string()))
}

async fn ws_chan_a() -> impl IntoResponse {
    respond(ws_chan("127.0.0.1:8093", "/ping-i").await)
}

async fn ws_chan_b() -> impl IntoResponse {
    respond(ws_chan("127.0.0.1:8094", "/ping-j").await)
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

// /blocking-a and /blocking-b: each dispatches a spawn_blocking closure that calls a
// distinct backend path. The closure runs on a blocking-pool thread that never handled
// the inbound request, so a thread-based lookup cannot attribute it. The suite asserts
// a clean-chain floor and zero misattribution on both builds (release registers the
// blocking task at Spawner::spawn_task, debug walks the ids).
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

// A synchronous HTTP/1 listener on 8095 served by std threads, next to the Tokio runtime:
// threads that never poll a task. /sync-a and /sync-b call the backend with ureq on the
// handling thread itself, so the parent is that thread's own server span, which OBI must
// keep resolving in a process that also runs Tokio. One request per connection, so every
// request is read on a fresh thread.
const SYNC_ADDR: &str = "0.0.0.0:8095";
const BACKEND_M: &str = "http://127.0.0.1:8093/ping-m";
const BACKEND_N: &str = "http://127.0.0.1:8094/ping-n";

fn serve_sync_listener() {
    let listener = std::net::TcpListener::bind(SYNC_ADDR).expect("bind the sync listener");
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        std::thread::spawn(move || handle_sync_request(stream));
    }
}

fn handle_sync_request(mut stream: std::net::TcpStream) {
    use std::io::{BufRead, BufReader, Write};

    let mut reader = BufReader::new(stream.try_clone().expect("clone the sync stream"));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap_or(0) == 0 || header == "\r\n" {
            break;
        }
    }

    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    let (status, body) = match path {
        "/sync-a" => sync_outcome(call_backend_blocking_url(BACKEND_M)),
        "/sync-b" => sync_outcome(call_backend_blocking_url(BACKEND_N)),
        "/health" => ("200 OK", "ok".to_string()),
        _ => ("404 Not Found", "not found".to_string()),
    };
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}

fn sync_outcome(result: Result<String, String>) -> (&'static str, String) {
    match result {
        Ok(body) => ("200 OK", body),
        Err(e) => ("500 Internal Server Error", e),
    }
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
        .route("/ws-spawn-b", get(ws_spawn_b))
        .route("/ws-direct-a", get(ws_direct_a))
        .route("/ws-direct-b", get(ws_direct_b))
        .route("/ws-pool-a", get(ws_pool_a))
        .route("/ws-pool-b", get(ws_pool_b))
        .route("/ws-chan-a", get(ws_chan_a))
        .route("/ws-chan-b", get(ws_chan_b));

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
    println!(
        "  GET :8095/sync-a|b   — std-thread listener -> ureq /ping-m|n (sync discrimination)"
    );

    std::thread::spawn(serve_sync_listener);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8092")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
