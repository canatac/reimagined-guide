use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;

#[derive(Serialize)]
pub struct LivenessResponse {
    pub status: &'static str,
}

#[derive(Serialize)]
pub struct ReadinessResponse {
    pub status: String,
    pub ping_ms: u128,
    pub database: &'static str,
}

/// Liveness probe: process is alive. Always returns 200.
pub async fn liveness() -> (StatusCode, Json<LivenessResponse>) {
    (StatusCode::OK, Json(LivenessResponse { status: "alive" }))
}

/// Readiness probe: MongoDB reachable. Returns 503 if ping fails or exceeds threshold.
pub async fn readiness(State(state): State<Arc<crate::AppState>>) -> (StatusCode, Json<ReadinessResponse>) {
    let start = Instant::now();
    let db = &state.mongo;
    match db.run_command(bson::doc! { "ping": 1 }, None).await {
        Ok(_) => {
            let ping_ms = start.elapsed().as_millis();
            if ping_ms > 5000 {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ReadinessResponse {
                        status: "unhealthy".to_string(),
                        ping_ms,
                        database: "mailserver",
                    }),
                )
            } else {
                (
                    StatusCode::OK,
                    Json(ReadinessResponse {
                        status: "ready".to_string(),
                        ping_ms,
                        database: "mailserver",
                    }),
                )
            }
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadinessResponse {
                status: "unhealthy".to_string(),
                ping_ms: start.elapsed().as_millis(),
                database: "mailserver",
            }),
        ),
    }
}

pub fn health_routes() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/api/health", get(liveness))
        .route("/api/health/ready", get(readiness))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use axum::Router;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn dummy_state() -> Arc<crate::AppState> {
        unimplemented!("test harness must provide a mock AppState with a Mongo client")
    }

    #[tokio::test]
    async fn liveness_always_200() {
        let app = Router::new().route("/api/health", get(liveness));
        let res = app
            .oneshot(Request::builder().uri("/api/health").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
