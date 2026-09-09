//! MTA-STS (Mail Transfer Agent Strict Transport Security) route registration
//! RFC 8461 — DNS-based TLS policy for outbound SMTP

use actix_web::web;
use crate::monitoring_handlers::{
    api_mta_sts_policy,
    api_mta_sts_validate,
    api_mta_sts_generate,
};

pub(crate) fn register_mta_sts_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/mta-sts/policy", web::get().to(api_mta_sts_policy));
    cfg.route("/api/v1/mta-sts/validate", web::get().to(api_mta_sts_validate));
    cfg.route("/api/v1/mta-sts/generate", web::post().to(api_mta_sts_generate));
}
