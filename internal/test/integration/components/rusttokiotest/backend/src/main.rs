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

async fn health() -> impl IntoResponse {
    "ok\n"
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/health", get(health))
        .route("/ping", get(ping))
        .route("/ping-a", get(ping_a))
        .route("/ping-b", get(ping_b));

    println!("backend listening on http://0.0.0.0:8093");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8093")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
