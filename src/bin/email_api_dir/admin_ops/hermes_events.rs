#![allow(unused_imports, dead_code)]
use super::*;

pub(crate) async fn api_hermes_run_events(path: web::Path<HermesRunPath>, req: HttpRequest) -> impl Responder {
    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let query_suffix = req
        .uri()
        .query()
        .filter(|q| !q.is_empty())
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let url = format!("{}/v1/runs/{}/events{}", base, path.run_id, query_suffix);

    let client = reqwest::Client::new();
    let upstream = match client
        .get(url)
        .bearer_auth(api_key)
        .header("Accept", "text/event-stream")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Hermes upstream unavailable"
            }));
        }
    };

    let status = upstream.status();
    if !status.is_success() {
        let body_json = match upstream.json::<serde_json::Value>().await {
            Ok(v) => v,
            Err(_) => serde_json::json!({ "error": "Hermes upstream error" }),
        };
        return HttpResponse::build(
            actix_web::http::StatusCode::from_u16(status.as_u16())
                .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
        )
        .json(body_json);
    }

    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("text/event-stream")
        .to_string();

    let bytes_stream = upstream
        .bytes_stream()
        .map_err(actix_web::error::ErrorBadGateway);

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .content_type(content_type)
    .insert_header(("Cache-Control", "no-cache"))
    .insert_header(("X-Accel-Buffering", "no"))
    .streaming(bytes_stream)
}

