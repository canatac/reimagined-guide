//! Prometheus metrics route registration

use actix_web::web;
use crate::monitoring_handlers::api_monitoring_prometheus;

pub(crate) fn register_prometheus_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/monitoring/metrics", web::get().to(api_monitoring_prometheus));
}
