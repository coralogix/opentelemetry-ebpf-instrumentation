// server: Axum on a single multi-thread work-stealing Tokio runtime (#[tokio::main]).
// tokio::spawn enqueues the task on the shared scheduler and any worker may run it, so
// an egress can run on a thread that never handled the inbound request; OBI attributes
// it by task lineage, not by thread. (actix-web is the other common shape: one
// current-thread runtime per worker, where tasks never migrate.)

use axum::{Router, routing::get, http::StatusCode, response::IntoResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BACKEND: &str = "http://127.0.0.1:8093/ping";

async fn call_backend(label: &str) -> Result<String, String> {
    call_backend_url(label, BACKEND).await
}

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

// /ws-direct: the handler awaits reqwest itself; no spawn.
async fn ws_direct() -> impl IntoResponse {
    println!(
        "[ws-direct] thread={:?}",
        std::thread::current().id()
    );
    respond(call_backend("ws-direct").await)
}

// /ws-spawn: one tokio::spawn between the handler and the call; the child may be stolen
// by another worker, so only the task lineage links it to the request.
async fn ws_spawn() -> impl IntoResponse {
    let handler_tid = std::thread::current().id();
    println!("[ws-spawn] handler thread={:?}", handler_tid);

    let handle = tokio::spawn(async move {
        // Yield once so the task leaves the worker's LIFO slot and an idle worker can steal it;
        // otherwise the spawning worker runs it and nothing migrates.
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

// Async discriminator backends, distinct from the spawn_blocking pair so the subtests never
// classify each other's traces.
const BACKEND_C: &str = "http://127.0.0.1:8093/ping-c";
// Every B side also targets port 8094, so the sides differ at the transport level
// (orig_dport) as well as by HTTP path.
const BACKEND_D: &str = "http://127.0.0.1:8094/ping-d";

// /ws-spawn-a, /ws-spawn-b: /ws-spawn with a distinct backend per side.
async fn ws_spawn_a() -> impl IntoResponse {
    let handler_tid = std::thread::current().id();
    let handle = tokio::spawn(async move {
        tokio::task::yield_now().await;
        let child_tid = std::thread::current().id();
        // migrated=true: the child resumed on another worker.
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

// The calling task opens its own TcpStream and writes it: the egress happens while the
// per-request task is current, unlike reqwest, where a connection task with no link to the
// request does the write. Connection: close, so nothing is pooled.
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

// /ws-direct-a, /ws-direct-b: /ws-spawn-a/b with a raw TcpStream write on the child task
// itself. A -> :8093/ping-e, B -> :8094/ping-f.
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

// Shared keep-alive client: every call after the first reuses the same hyper connection-
// driver task, whose lineage points at the first request. Those egresses must fail closed.
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

// /ws-pool-a, /ws-pool-b: /ws-spawn-a/b through the shared client, so concurrent A/B
// requests interleave on reused connections and driver tasks.
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

// One long-lived worker task (actor pattern), spawned lazily by the first request so its
// lineage sits under that request's keep-alive connection task, re-anchored by every later
// request. It serves both sides, so a stale lineage crosses the A/B boundary; every worker
// egress must fail closed once its spawn-time epoch is stale.
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
                // The worker does the egress itself, so the egress task identity is never the handler's.
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

// /blocking: the call runs on a blocking-pool OS thread, not an async worker.
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

fn call_backend_blocking_url(url: &str) -> Result<String, String> {
    ureq::get(url)
        .call()
        .map_err(|e| e.to_string())
        .and_then(|r| r.into_string().map_err(|e| e.to_string()))
}

const BACKEND_A: &str = "http://127.0.0.1:8093/ping-a";
const BACKEND_B: &str = "http://127.0.0.1:8093/ping-b";

// /blocking-a, /blocking-b: /blocking with a distinct backend per side; the blocking-pool
// thread never handled the inbound request.
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

// A std-thread HTTP/1 listener on 8095 beside the Tokio runtime: /sync-a and /sync-b call
// the backend on the handling thread itself, so the parent must be that thread's own server
// span. Connection: close, so every request is read on a fresh thread.
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
