// Frontend server for testing Tokio async context propagation in OBI.
//
// Three endpoints exercise increasing depths of tokio::spawn nesting.
// In each case OBI should produce an outgoing client span whose parentSpanID
// matches the spanID of the inbound server span for that endpoint.
//
// Start the backend first:  cargo run -p backend
// Then start this server:   cargo run -p server
//
// Test with:
//   curl http://localhost:8090/direct   # handler calls reqwest directly
//   curl http://localhost:8090/spawn    # one tokio::spawn wraps the reqwest call
//   curl http://localhost:8090/nested  # two nested spawns before the reqwest call

use actix_web::{web, App, HttpResponse, HttpServer};

const BACKEND: &str = "http://127.0.0.1:8091/ping";

async fn call_backend(label: &str) -> Result<String, String> {
    reqwest::get(BACKEND)
        .await
        .map_err(|e| format!("[{}] connect error: {}", label, e))?
        .text()
        .await
        .map_err(|e| format!("[{}] read error: {}", label, e))
}

fn ok_or_500(result: Result<String, String>, label: &str) -> HttpResponse {
    match result {
        Ok(body) => {
            println!("[{}] backend replied: {}", label, body);
            HttpResponse::Ok().body(body)
        }
        Err(e) => {
            eprintln!("{}", e);
            HttpResponse::InternalServerError().body(e)
        }
    }
}

// /direct — the async handler awaits reqwest directly, no tokio::spawn.
// The same task that accepted the connection makes the outgoing call, so OBI
// can find the parent via thread state alone.  This is the baseline case.
async fn direct() -> HttpResponse {
    println!("[direct] calling backend");
    ok_or_500(call_backend("direct").await, "direct")
}

// /spawn — one level of tokio::spawn between the handler and the outgoing call.
// The task that calls reqwest is a child of the handler task.  OBI must walk
// the task ancestry (child -> handler -> conn_valid) to find the parent span.
async fn spawn() -> HttpResponse {
    println!("[spawn] spawning task");
    let handle = tokio::spawn(async {
        println!("[spawn] task calling backend");
        call_backend("spawn").await
    });
    ok_or_500(handle.await.unwrap_or_else(|e| Err(e.to_string())), "spawn")
}

// /nested — two levels of tokio::spawn.
// handler spawns task A -> task A spawns task B -> task B calls reqwest.
// OBI must walk depth-2 ancestry (B -> A -> handler -> conn_valid).
async fn nested() -> HttpResponse {
    println!("[nested] spawning outer task");
    let handle = tokio::spawn(async {
        println!("[nested] outer task spawning inner task");
        let inner = tokio::spawn(async {
            println!("[nested] inner task calling backend");
            call_backend("nested").await
        });
        inner.await.unwrap_or_else(|e| Err(e.to_string()))
    });
    ok_or_500(handle.await.unwrap_or_else(|e| Err(e.to_string())), "nested")
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().body("ok\n")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("server listening on http://0.0.0.0:8090");
    println!("  GET /health  — liveness check");
    println!("  GET /direct  — reqwest in handler task (depth 0)");
    println!("  GET /spawn   — reqwest in spawned task (depth 1)");
    println!("  GET /nested  — reqwest in doubly-spawned task (depth 2)");
    HttpServer::new(|| {
        App::new()
            .service(web::resource("/health").route(web::get().to(health)))
            .service(web::resource("/direct").route(web::get().to(direct)))
            .service(web::resource("/spawn").route(web::get().to(spawn)))
            .service(web::resource("/nested").route(web::get().to(nested)))
    })
    .bind(("0.0.0.0", 8090))?
    .run()
    .await
}
