// backend: downstream service for server (work-stealing test).
// Echoes the traceparent header so the test can verify propagation from logs.
use axum::{Router, routing::get, http::HeaderMap, response::IntoResponse};

async fn ping(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping  traceparent={}", traceparent);
    format!("pong traceparent={}", traceparent)
}

// /ping-a and /ping-b are the A/B endpoints for the probe-discrimination test.
// They are distinct url.path values so OBI emits distinct backend server spans;
// the test uses that as ground truth (a /ping-b span appearing under an
// /blocking-a server span is a definite cross-service misattribution).
async fn ping_a(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-a  traceparent={}", traceparent);
    format!("pong-a traceparent={}", traceparent)
}

async fn ping_b(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-b  traceparent={}", traceparent);
    format!("pong-b traceparent={}", traceparent)
}

// /ping-c and /ping-d are the async A/B discriminator's backends (kept distinct
// from /ping-a and /ping-b so the async and spawn_blocking subtests never
// cross-classify each other's traces).
async fn ping_c(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-c  traceparent={}", traceparent);
    format!("pong-c traceparent={}", traceparent)
}

async fn ping_d(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-d  traceparent={}", traceparent);
    format!("pong-d traceparent={}", traceparent)
}

// /ping-e and /ping-f are the DIRECT-I/O (Shape B) A/B discriminator's backends,
// kept distinct from the reqwest paths (/ping-c, /ping-d) so the shapes never
// cross-classify.
async fn ping_e(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-e  traceparent={}", traceparent);
    format!("pong-e traceparent={}", traceparent)
}

async fn ping_f(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-f  traceparent={}", traceparent);
    format!("pong-f traceparent={}", traceparent)
}

// /ping-g and /ping-h are the SHARED-CLIENT (pooled keep-alive reuse) A/B
// discriminator's backends. Kept distinct from every other pair so pool-reuse
// misattribution (a request resolving a PREVIOUS request's trace through a reused
// hyper connection-driver task) is classified on its own.
async fn ping_g(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-g  traceparent={}", traceparent);
    format!("pong-g traceparent={}", traceparent)
}

async fn ping_h(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-h  traceparent={}", traceparent);
    format!("pong-h traceparent={}", traceparent)
}

// /ping-i and /ping-j are the CHANNEL-HANDOFF (long-lived worker task) A/B
// discriminator's backends: one worker task serves BOTH sides, so a stale lineage
// on it would cross the A/B boundary and surface as contamination.
async fn ping_i(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-i  traceparent={}", traceparent);
    format!("pong-i traceparent={}", traceparent)
}

async fn ping_j(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-j  traceparent={}", traceparent);
    format!("pong-j traceparent={}", traceparent)
}

// /ping-k and /ping-l are the EVICTED-MAILBOX A/B discriminator's backends: a lineage the
// mailbox's wake adopted from one request would cross the A/B boundary. The response is
// held for MAILBOX_HOLD so one request's window spans several of the mailbox's jobs.
const MAILBOX_HOLD: std::time::Duration = std::time::Duration::from_millis(20);

async fn ping_k(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-k  traceparent={}", traceparent);
    tokio::time::sleep(MAILBOX_HOLD).await;
    format!("pong-k traceparent={}", traceparent)
}

async fn ping_l(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-l  traceparent={}", traceparent);
    tokio::time::sleep(MAILBOX_HOLD).await;
    format!("pong-l traceparent={}", traceparent)
}

// /ping-m and /ping-n are the SYNC-THREAD A/B discriminator's backends: the server's std
// threads call them, and their parent must be the calling thread's own server span.
async fn ping_m(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-m  traceparent={}", traceparent);
    format!("pong-m traceparent={}", traceparent)
}

async fn ping_n(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-n  traceparent={}", traceparent);
    format!("pong-n traceparent={}", traceparent)
}

async fn health() -> impl IntoResponse {
    "ok\n"
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/health", get(health))
        .route("/ping", get(ping))
        .route("/ping-a", get(ping_a))
        .route("/ping-b", get(ping_b))
        .route("/ping-c", get(ping_c))
        .route("/ping-d", get(ping_d))
        .route("/ping-e", get(ping_e))
        .route("/ping-f", get(ping_f))
        .route("/ping-g", get(ping_g))
        .route("/ping-h", get(ping_h))
        .route("/ping-i", get(ping_i))
        .route("/ping-j", get(ping_j))
        .route("/ping-k", get(ping_k))
        .route("/ping-l", get(ping_l))
        .route("/ping-m", get(ping_m))
        .route("/ping-n", get(ping_n));

    // 8094 is a second listener for the A/B discriminators: every B side targets it, so
    // the sides differ by port (orig_dport) as well as by HTTP path.
    println!("backend listening on http://0.0.0.0:8093 and :8094");
    let l8093 = tokio::net::TcpListener::bind("0.0.0.0:8093").await.unwrap();
    let l8094 = tokio::net::TcpListener::bind("0.0.0.0:8094").await.unwrap();
    let app2 = app.clone();
    tokio::spawn(async move { axum::serve(l8094, app2).await.unwrap(); });
    axum::serve(l8093, app).await.unwrap();
}
