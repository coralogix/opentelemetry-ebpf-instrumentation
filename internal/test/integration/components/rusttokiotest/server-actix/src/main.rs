// server-actix: actix-web, one current-thread Tokio runtime per worker thread. Tasks never
// migrate: the handler future is polled inside actix's per-connection dispatcher task, and
// tokio::spawn / spawn_local children run later on the same thread. OBI resolves a Tokio
// process only through the task walks, so this binary proves they carry the shapes a
// current-thread app uses. Same backend as the axum server; every B side targets port 8094
// as well as its own path, so the sides differ at the transport level (orig_dport) too.
//
// Start backend first:  cargo run -p backend
// Then:                  cargo run -p server-actix

use std::sync::OnceLock;

use actix_web::{web, App, HttpResponse, HttpServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

const WORKERS: usize = 4;

fn respond(result: Result<String, String>) -> HttpResponse {
    match result {
        Ok(body) => HttpResponse::Ok().body(body),
        Err(e) => HttpResponse::InternalServerError().body(e),
    }
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().body("ok")
}

// Fresh reqwest client per call: every connection driver is first-use and a child of the
// calling task.
async fn call_backend(label: &str, url: &str) -> Result<String, String> {
    reqwest::get(url)
        .await
        .map_err(|e| format!("[{}] connect error: {}", label, e))?
        .text()
        .await
        .map_err(|e| format!("[{}] read error: {}", label, e))
}

// Raw TcpStream request written by the calling task itself (no connection task),
// Connection: close so nothing is pooled.
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

// /direct-a and /direct-b: the handler calls the backend itself, inside the dispatcher task
// the inbound request was anchored on (depth 0).
async fn direct_a() -> HttpResponse {
    respond(call_backend("direct-a", "http://127.0.0.1:8093/ping-a").await)
}

async fn direct_b() -> HttpResponse {
    respond(call_backend("direct-b", "http://127.0.0.1:8094/ping-b").await)
}

// /spawn-a and /spawn-b: a tokio::spawn child calls the backend. It runs later on the same
// thread; its lineage parent is the dispatcher task (depth 1).
async fn spawn_a() -> HttpResponse {
    let handle = tokio::spawn(async move {
        tokio::task::yield_now().await;
        call_backend("spawn-a", "http://127.0.0.1:8093/ping-c").await
    });
    respond(handle.await.unwrap_or_else(|e| Err(e.to_string())))
}

async fn spawn_b() -> HttpResponse {
    let handle = tokio::spawn(async move {
        tokio::task::yield_now().await;
        call_backend("spawn-b", "http://127.0.0.1:8094/ping-d").await
    });
    respond(handle.await.unwrap_or_else(|e| Err(e.to_string())))
}

// /local-a and /local-b: a spawn_local child (actix workers run inside a LocalSet) writes
// the request on its own TcpStream, so the egress happens while the LocalSet task is
// current (depth 1).
async fn local_a() -> HttpResponse {
    let handle = tokio::task::spawn_local(async move {
        tokio::task::yield_now().await;
        call_backend_direct("local-a", "127.0.0.1:8093", "/ping-e").await
    });
    respond(handle.await.unwrap_or_else(|e| Err(e.to_string())))
}

async fn local_b() -> HttpResponse {
    let handle = tokio::task::spawn_local(async move {
        tokio::task::yield_now().await;
        call_backend_direct("local-b", "127.0.0.1:8094", "/ping-f").await
    });
    respond(handle.await.unwrap_or_else(|e| Err(e.to_string())))
}

// /nested-a and /nested-b: spawn_local, then tokio::spawn inside it, then the call: a
// depth-2 lineage mixing both spawn kinds.
async fn nested_a() -> HttpResponse {
    let outer = tokio::task::spawn_local(async move {
        tokio::task::yield_now().await;
        let inner = tokio::spawn(async move {
            tokio::task::yield_now().await;
            call_backend("nested-a", "http://127.0.0.1:8093/ping-g").await
        });
        inner.await.unwrap_or_else(|e| Err(e.to_string()))
    });
    respond(outer.await.unwrap_or_else(|e| Err(e.to_string())))
}

async fn nested_b() -> HttpResponse {
    let outer = tokio::task::spawn_local(async move {
        tokio::task::yield_now().await;
        let inner = tokio::spawn(async move {
            tokio::task::yield_now().await;
            call_backend("nested-b", "http://127.0.0.1:8094/ping-h").await
        });
        inner.await.unwrap_or_else(|e| Err(e.to_string()))
    });
    respond(outer.await.unwrap_or_else(|e| Err(e.to_string())))
}

// One reqwest client shared by the worker runtimes: a pooled connection's driver task lives
// on the runtime that opened it and serves later requests from the other workers, so its
// lineage points at the request that opened it. Those egresses must fail closed.
static POOL_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

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

async fn pool_a() -> HttpResponse {
    respond(call_backend_pooled("pool-a", "http://127.0.0.1:8093/ping-i").await)
}

async fn pool_b() -> HttpResponse {
    respond(call_backend_pooled("pool-b", "http://127.0.0.1:8094/ping-j").await)
}

// One mailbox task for the whole process, a long-lived LocalSet task: /evict-fill spawns it
// under its own request (whose window closes with that response, so nothing resolves
// through it afterwards), then spawns FILL_TASKS parked tasks so OBI's task map evicts the
// mailbox's entry. /mbox-a and /mbox-b hand their backend call to the mailbox over a
// channel from any worker; it runs each job on a spawn_local child. A wake that
// re-registered the evicted mailbox under the waking request would make every job it then
// runs resolve that request, cross-side.
const FILL_TASKS: usize = 50_000;

struct MailboxJob {
    label: &'static str,
    addr: &'static str,
    path: &'static str,
    reply: oneshot::Sender<Result<String, String>>,
}

static MAILBOX: OnceLock<mpsc::UnboundedSender<MailboxJob>> = OnceLock::new();

fn start_mailbox() -> mpsc::UnboundedSender<MailboxJob> {
    let (tx, mut rx) = mpsc::unbounded_channel::<MailboxJob>();
    tokio::task::spawn_local(async move {
        while let Some(job) = rx.recv().await {
            tokio::task::spawn_local(async move {
                let result = call_backend_direct(job.label, job.addr, job.path).await;
                let _ = job.reply.send(result);
            });
        }
    });
    tx
}

async fn evict_fill() -> HttpResponse {
    MAILBOX.get_or_init(start_mailbox);
    for _ in 0..FILL_TASKS {
        tokio::task::spawn_local(std::future::pending::<()>());
    }
    HttpResponse::Ok().body(format!("spawned {} parked tasks", FILL_TASKS))
}

async fn call_backend_mailbox(
    label: &'static str,
    addr: &'static str,
    path: &'static str,
) -> Result<String, String> {
    let Some(tx) = MAILBOX.get() else {
        return Err(format!(
            "[{}] mailbox not started: call /evict-fill first",
            label
        ));
    };
    let (reply, rx) = oneshot::channel();
    tx.send(MailboxJob {
        label,
        addr,
        path,
        reply,
    })
    .map_err(|_| format!("[{}] mailbox gone", label))?;
    rx.await
        .unwrap_or_else(|_| Err(format!("[{}] mailbox dropped the job", label)))
}

async fn mbox_a() -> HttpResponse {
    respond(call_backend_mailbox("mbox-a", "127.0.0.1:8093", "/ping-k").await)
}

async fn mbox_b() -> HttpResponse {
    respond(call_backend_mailbox("mbox-b", "127.0.0.1:8094", "/ping-l").await)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!(
        "server (current-thread, {} workers) listening on http://0.0.0.0:8092",
        WORKERS
    );
    HttpServer::new(|| {
        App::new()
            .route("/health", web::get().to(health))
            .route("/direct-a", web::get().to(direct_a))
            .route("/direct-b", web::get().to(direct_b))
            .route("/spawn-a", web::get().to(spawn_a))
            .route("/spawn-b", web::get().to(spawn_b))
            .route("/local-a", web::get().to(local_a))
            .route("/local-b", web::get().to(local_b))
            .route("/nested-a", web::get().to(nested_a))
            .route("/nested-b", web::get().to(nested_b))
            .route("/pool-a", web::get().to(pool_a))
            .route("/pool-b", web::get().to(pool_b))
            .route("/evict-fill", web::get().to(evict_fill))
            .route("/mbox-a", web::get().to(mbox_a))
            .route("/mbox-b", web::get().to(mbox_b))
    })
    .workers(WORKERS)
    .bind(("0.0.0.0", 8092))?
    .run()
    .await
}
