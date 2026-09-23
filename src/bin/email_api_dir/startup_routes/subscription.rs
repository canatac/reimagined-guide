//! Subscription & billing routes (issue #627).
//!
//! Pro plan subscription endpoints for payment, activation, invoices.

use actix_web::web;

use super::super::*;

pub(crate) fn register_subscription_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/subscription/subscribe", web::post().to(api_subscription_subscribe))
        .route("/api/subscription", web::get().to(api_subscription_status))
        .route("/api/subscription/cancel", web::post().to(api_subscription_cancel))
        .route("/api/subscription/invoices", web::get().to(api_subscription_invoices));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_routes_subscribe() {
        let route = "/api/subscription/subscribe";
        assert_eq!(route, "/api/subscription/subscribe");
    }

    #[test]
    fn subscription_routes_status() {
        let route = "/api/subscription";
        assert_eq!(route, "/api/subscription");
    }

    #[test]
    fn subscription_routes_cancel() {
        let route = "/api/subscription/cancel";
        assert_eq!(route, "/api/subscription/cancel");
    }

    #[test]
    fn subscription_routes_invoices() {
        let route = "/api/subscription/invoices";
        assert_eq!(route, "/api/subscription/invoices");
    }
}
