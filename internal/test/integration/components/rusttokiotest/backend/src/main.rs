// Simple backend server that acts as the downstream service.
// The frontend server (server/) makes async outgoing HTTP calls to this process.
// OBI should produce a client span (from server) whose parentSpanID matches
// the server span of whichever /direct, /spawn, or /nested endpoint triggered it.
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};

async fn ping(req: HttpRequest) -> HttpResponse {
    // Echo back any traceparent header so we can verify propagation from logs.
    let traceparent = req
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)");
    println!("backend /ping  traceparent={}", traceparent);
    HttpResponse::Ok().body(format!("pong traceparent={}", traceparent))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("backend listening on http://0.0.0.0:8091");
    HttpServer::new(|| App::new().service(web::resource("/ping").route(web::get().to(ping))))
        .bind(("0.0.0.0", 8091))?
        .run()
        .await
}
