// backend: echoes the traceparent header on every /ping* route.
use axum::{Router, routing::get, http::HeaderMap, response::IntoResponse};

async fn ping(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping  traceparent={}", traceparent);
    format!("pong traceparent={}", traceparent)
}

// One route pair per discrimination subtest (red_test_rust_tokio_test.go); distinct paths
// keep the subtests from classifying each other's traces.
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

// /ping-k and /ping-l hold the response for MAILBOX_HOLD so one request's window spans
// several mailbox jobs.
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

async fn ping_o(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-o  traceparent={}", traceparent);
    format!("pong-o traceparent={}", traceparent)
}

async fn ping_p(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-p  traceparent={}", traceparent);
    format!("pong-p traceparent={}", traceparent)
}

async fn ping_q(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-q  traceparent={}", traceparent);
    format!("pong-q traceparent={}", traceparent)
}

async fn ping_r(headers: HeaderMap) -> impl IntoResponse {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping-r  traceparent={}", traceparent);
    format!("pong-r traceparent={}", traceparent)
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
        .route("/ping-n", get(ping_n))
        .route("/ping-o", get(ping_o))
        .route("/ping-p", get(ping_p))
        .route("/ping-q", get(ping_q))
        .route("/ping-r", get(ping_r));

    // With a port argument the process serves that port alone (the image runs one backend per
    // port; see the Dockerfile for why). No argument keeps both listeners for local use.
    if let Some(port) = std::env::args().nth(1) {
        println!("backend listening on http://0.0.0.0:{}", port);
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
            .await
            .unwrap();
        axum::serve(listener, app).await.unwrap();
        return;
    }
    println!("backend listening on http://0.0.0.0:8093 and :8094");
    let l8093 = tokio::net::TcpListener::bind("0.0.0.0:8093").await.unwrap();
    let l8094 = tokio::net::TcpListener::bind("0.0.0.0:8094").await.unwrap();
    let app2 = app.clone();
    tokio::spawn(async move { axum::serve(l8094, app2).await.unwrap(); });
    axum::serve(l8093, app).await.unwrap();
}
