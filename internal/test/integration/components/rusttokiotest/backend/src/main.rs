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

async fn health() -> impl IntoResponse {
    "ok\n"
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/health", get(health))
        .route("/ping", get(ping));

    println!("backend listening on http://0.0.0.0:8093");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8093")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
