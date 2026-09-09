//! Dashboard metrics route registration

use actix_web::web;
use crate::monitoring_handlers::api_monitoring_dashboard;

pub(crate) fn register_dashboard_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/monitoring/dashboard", web::get().to(api_monitoring_dashboard));
}
