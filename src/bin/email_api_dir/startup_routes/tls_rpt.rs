//! TLS-RPT (TLS Reporting) route registration

use actix_web::web;
use crate::monitoring_handlers::{
    api_tls_rpt_import,
    api_tls_rpt_list,
    api_tls_rpt_aggregate,
    api_tls_rpt_trends,
    api_tls_rpt_failures,
    api_tls_rpt_alerts_config,
};

pub(crate) fn register_tls_rpt_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/tls-rpt/reports", web::post().to(api_tls_rpt_import));
    cfg.route("/api/v1/tls-rpt/reports", web::get().to(api_tls_rpt_list));
    cfg.route("/api/v1/tls-rpt/aggregate", web::get().to(api_tls_rpt_aggregate));
    cfg.route("/api/v1/tls-rpt/trends", web::get().to(api_tls_rpt_trends));
    cfg.route("/api/v1/tls-rpt/failures", web::get().to(api_tls_rpt_failures));
    cfg.route("/api/v1/tls-rpt/alerts", web::get().to(api_tls_rpt_alerts_config));
}
