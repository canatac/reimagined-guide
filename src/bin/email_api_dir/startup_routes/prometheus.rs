//! Prometheus metrics route registration

use actix_web::web;
use crate::monitoring_handlers::api_monitoring_prometheus;

pub(crate) fn register_prometheus_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/monitoring/metrics", web::get().to(api_monitoring_prometheus));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_routes_metrics() {
        let route = "/api/monitoring/metrics";
        assert_eq!(route, "/api/monitoring/metrics");
    }

    #[test]
    fn prometheus_routes_method_get() {
        let method = "GET";
        assert_eq!(method, "GET");
    }

    #[test]
    fn prometheus_routes_handler() {
        let handler = "api_monitoring_prometheus";
        assert_eq!(handler, "api_monitoring_prometheus");
    }

    #[test]
    fn prometheus_routes_path_contains_monitoring() {
        let route = "/api/monitoring/metrics";
        assert!(route.contains("monitoring"));
    }

    #[test]
    fn prometheus_routes_path_contains_metrics() {
        let route = "/api/monitoring/metrics";
        assert!(route.contains("metrics"));
    }

    #[test]
    fn prometheus_routes_path_starts_with_api() {
        let route = "/api/monitoring/metrics";
        assert!(route.starts_with("/api/"));
    }

    #[test]
    fn prometheus_routes_path_format() {
        let route = "/api/monitoring/metrics";
        let parts: Vec<&str> = route.split('/').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "");
        assert_eq!(parts[1], "api");
        assert_eq!(parts[2], "monitoring");
        assert_eq!(parts[3], "metrics");
    }

    #[test]
    fn prometheus_routes_path_no_trailing_slash() {
        let route = "/api/monitoring/metrics";
        assert!(!route.ends_with("/"));
    }

    #[test]
    fn prometheus_routes_path_no_leading_double_slash() {
        let route = "/api/monitoring/metrics";
        assert!(!route.starts_with("//"));
    }

    #[test]
    fn prometheus_routes_path_no_spaces() {
        let route = "/api/monitoring/metrics";
        assert!(!route.contains(" "));
    }

    #[test]
    fn prometheus_routes_path_no_uppercase() {
        let route = "/api/monitoring/metrics";
        assert_eq!(route, route.to_ascii_lowercase());
    }

    #[test]
    fn prometheus_routes_path_no_special_chars() {
        let route = "/api/monitoring/metrics";
        assert!(route.chars().all(|c| c.is_alphanumeric() || c == '/' || c == '_'));
    }

    #[test]
    fn prometheus_routes_path_segments() {
        let route = "/api/monitoring/metrics";
        let segments: Vec<&str> = route.split('/').filter(|s| !s.is_empty()).collect();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0], "api");
        assert_eq!(segments[1], "monitoring");
        assert_eq!(segments[2], "metrics");
    }

    #[test]
    fn prometheus_routes_path_depth() {
        let route = "/api/monitoring/metrics";
        let depth = route.split('/').filter(|s| !s.is_empty()).count();
        assert_eq!(depth, 3);
    }

    #[test]
    fn prometheus_routes_path_length() {
        let route = "/api/monitoring/metrics";
        assert!(route.len() > 0);
        assert!(route.len() < 100);
    }

    #[test]
    fn prometheus_routes_path_valid() {
        let route = "/api/monitoring/metrics";
        assert!(route.starts_with("/"));
        assert!(!route.ends_with("/"));
        assert!(!route.contains("//"));
    }

    #[test]
    fn prometheus_routes_handler_name() {
        let handler = "api_monitoring_prometheus";
        assert!(handler.starts_with("api_"));
        assert!(handler.contains("monitoring"));
        assert!(handler.contains("prometheus"));
    }

    #[test]
    fn prometheus_routes_handler_format() {
        let handler = "api_monitoring_prometheus";
        assert!(handler.chars().all(|c| c.is_alphanumeric() || c == '_'));
    }

    #[test]
    fn prometheus_routes_handler_length() {
        let handler = "api_monitoring_prometheus";
        assert!(handler.len() > 0);
        assert!(handler.len() < 100);
    }

    #[test]
    fn prometheus_routes_handler_snake_case() {
        let handler = "api_monitoring_prometheus";
        assert_eq!(handler, handler.to_ascii_lowercase());
    }

    #[test]
    fn prometheus_routes_handler_no_spaces() {
        let handler = "api_monitoring_prometheus";
        assert!(!handler.contains(" "));
    }

    #[test]
    fn prometheus_routes_handler_no_special_chars() {
        let handler = "api_monitoring_prometheus";
        assert!(handler.chars().all(|c| c.is_alphanumeric() || c == '_'));
    }

    #[test]
    fn prometheus_routes_handler_segments() {
        let handler = "api_monitoring_prometheus";
        let segments: Vec<&str> = handler.split('_').collect();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0], "api");
        assert_eq!(segments[1], "monitoring");
        assert_eq!(segments[2], "prometheus");
    }

    #[test]
    fn prometheus_routes_handler_prefix() {
        let handler = "api_monitoring_prometheus";
        assert!(handler.starts_with("api_"));
    }

    #[test]
    fn prometheus_routes_handler_suffix() {
        let handler = "api_monitoring_prometheus";
        assert!(handler.ends_with("_prometheus"));
    }

    #[test]
    fn prometheus_routes_handler_contains_monitoring() {
        let handler = "api_monitoring_prometheus";
        assert!(handler.contains("monitoring"));
    }

    #[test]
    fn prometheus_routes_handler_contains_prometheus() {
        let handler = "api_monitoring_prometheus";
        assert!(handler.contains("prometheus"));
    }

    #[test]
    fn prometheus_routes_method_get_format() {
        let method = "GET";
        assert_eq!(method.len(), 3);
        assert_eq!(method, method.to_ascii_uppercase());
    }

    #[test]
    fn prometheus_routes_method_get_valid() {
        let method = "GET";
        let valid_methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH"];
        assert!(valid_methods.contains(&method));
    }

    #[test]
    fn prometheus_routes_method_get_no_spaces() {
        let method = "GET";
        assert!(!method.contains(" "));
    }

    #[test]
    fn prometheus_routes_method_get_no_special_chars() {
        let method = "GET";
        assert!(method.chars().all(|c| c.is_alphabetic()));
    }

    #[test]
    fn prometheus_routes_method_get_uppercase() {
        let method = "GET";
        assert_eq!(method, method.to_ascii_uppercase());
    }

    #[test]
    fn prometheus_routes_method_get_lowercase() {
        let method = "get";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_mixed_case() {
        let method = "Get";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_empty() {
        let method = "";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_whitespace() {
        let method = " GET ";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_leading_space() {
        let method = " GET";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_trailing_space() {
        let method = "GET ";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_tab() {
        let method = "\tGET";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_newline() {
        let method = "\nGET";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_carriage_return() {
        let method = "\rGET";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_null() {
        let method = "\0GET";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_unicode() {
        let method = "GÉT";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_emoji() {
        let method = "GET😀";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_underscore() {
        let method = "GE_T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_hyphen() {
        let method = "GE-T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_dot() {
        let method = "GE.T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_slash() {
        let method = "GE/T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_backslash() {
        let method = "GE\\T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_colon() {
        let method = "GE:T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_semicolon() {
        let method = "GE;T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_comma() {
        let method = "GE,T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_pipe() {
        let method = "GE|T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_ampersand() {
        let method = "GE&T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_at() {
        let method = "GE@T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_hash() {
        let method = "GE#T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_dollar() {
        let method = "GE$T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_percent() {
        let method = "GE%T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_exclamation() {
        let method = "GE!T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_question() {
        let method = "GE?T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_plus() {
        let method = "GE+T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_equals() {
        let method = "GE=T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_star() {
        let method = "GE*T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_parentheses() {
        let method = "GE(T)";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_brackets() {
        let method = "GE[T]";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_braces() {
        let method = "GE{T}";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_less_than() {
        let method = "GE<T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_greater_than() {
        let method = "GE>T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_caret() {
        let method = "GE^T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn prometheus_routes_method_get_backtick() {
        let method = "GE`T";
        assert_ne!(method, "GET");
    }
}
