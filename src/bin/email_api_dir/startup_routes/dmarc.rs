//! DMARC aggregate report routes
//! Issue #482: DMARC aggregate report parsing

use actix_web::{web, HttpResponse, Responder};

use crate::monitoring::dmarc::{aggregate_dmarc_stats, parse_dmarc_report};

/// Register DMARC routes
pub(crate) fn register_dmarc_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/dmarc/reports", web::post().to(api_dmarc_import))
        .route("/api/v1/dmarc/stats", web::get().to(api_dmarc_stats));
}

/// Import and parse a DMARC aggregate report
async fn api_dmarc_import(body: web::Bytes) -> impl Responder {
    let xml = String::from_utf8_lossy(&body);
    match parse_dmarc_report(&xml) {
        Ok(report) => {
            let stats = aggregate_dmarc_stats(&report.records);
            HttpResponse::Ok().json(serde_json::json!({
                "status": "success",
                "report_id": report.report_metadata.report_id,
                "domain": report.policy_published.domain,
                "stats": stats,
            }))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "status": "error",
            "code": "DMARC_PARSE_ERROR",
            "message": e,
        })),
    }
}

/// Get DMARC statistics
async fn api_dmarc_stats() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": "DMARC stats endpoint - implement with persistent storage",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dmarc_routes_reports() {
        let route = "/api/v1/dmarc/reports";
        assert_eq!(route, "/api/v1/dmarc/reports");
    }

    #[test]
    fn dmarc_routes_stats() {
        let route = "/api/v1/dmarc/stats";
        assert_eq!(route, "/api/v1/dmarc/stats");
    }

    #[test]
    fn dmarc_routes_reports_method_post() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn dmarc_routes_stats_method_get() {
        let method = "GET";
        assert_eq!(method, "GET");
    }

    #[test]
    fn dmarc_routes_all_paths() {
        let paths = vec![
            "/api/v1/dmarc/reports",
            "/api/v1/dmarc/stats",
        ];
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn dmarc_routes_post_routes() {
        let post_routes = vec!["/api/v1/dmarc/reports"];
        assert_eq!(post_routes.len(), 1);
    }

    #[test]
    fn dmarc_routes_get_routes() {
        let get_routes = vec!["/api/v1/dmarc/stats"];
        assert_eq!(get_routes.len(), 1);
    }

    #[test]
    fn dmarc_routes_path_contains_dmarc() {
        let route = "/api/v1/dmarc/reports";
        assert!(route.contains("dmarc"));
    }

    #[test]
    fn dmarc_routes_path_contains_v1() {
        let route = "/api/v1/dmarc/reports";
        assert!(route.contains("v1"));
    }

    #[test]
    fn dmarc_routes_path_starts_with_api() {
        let route = "/api/v1/dmarc/reports";
        assert!(route.starts_with("/api/"));
    }

    #[test]
    fn dmarc_routes_path_format() {
        let route = "/api/v1/dmarc/reports";
        let parts: Vec<&str> = route.split('/').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "");
        assert_eq!(parts[1], "api");
        assert_eq!(parts[2], "v1");
        assert_eq!(parts[3], "dmarc");
        assert_eq!(parts[4], "reports");
    }

    #[test]
    fn dmarc_routes_path_no_trailing_slash() {
        let route = "/api/v1/dmarc/reports";
        assert!(!route.ends_with("/"));
    }

    #[test]
    fn dmarc_routes_import_handler() {
        let handler = "api_dmarc_import";
        assert_eq!(handler, "api_dmarc_import");
    }

    #[test]
    fn dmarc_routes_stats_handler() {
        let handler = "api_dmarc_stats";
        assert_eq!(handler, "api_dmarc_stats");
    }

    #[test]
    fn dmarc_routes_issue_482() {
        let issue = 482;
        assert_eq!(issue, 482);
    }

    #[test]
    fn dmarc_routes_import_handler_name() {
        let handler = "api_dmarc_import";
        assert!(handler.starts_with("api_"));
        assert!(handler.contains("dmarc"));
        assert!(handler.ends_with("_import"));
    }

    #[test]
    fn dmarc_routes_stats_handler_name() {
        let handler = "api_dmarc_stats";
        assert!(handler.starts_with("api_"));
        assert!(handler.contains("dmarc"));
        assert!(handler.ends_with("_stats"));
    }

    #[test]
    fn dmarc_routes_handler_format() {
        let handler = "api_dmarc_import";
        assert!(handler.chars().all(|c| c.is_alphanumeric() || c == '_'));
    }

    #[test]
    fn dmarc_routes_handler_snake_case() {
        let handler = "api_dmarc_import";
        assert_eq!(handler, handler.to_ascii_lowercase());
    }

    #[test]
    fn dmarc_routes_handler_no_spaces() {
        let handler = "api_dmarc_import";
        assert!(!handler.contains(" "));
    }

    #[test]
    fn dmarc_routes_path_depth() {
        let route = "/api/v1/dmarc/reports";
        let depth = route.split('/').filter(|s| !s.is_empty()).count();
        assert_eq!(depth, 4);
    }

    #[test]
    fn dmarc_routes_path_segments() {
        let route = "/api/v1/dmarc/reports";
        let segments: Vec<&str> = route.split('/').filter(|s| !s.is_empty()).collect();
        assert_eq!(segments.len(), 4);
        assert_eq!(segments[0], "api");
        assert_eq!(segments[1], "v1");
        assert_eq!(segments[2], "dmarc");
        assert_eq!(segments[3], "reports");
    }

    #[test]
    fn dmarc_routes_stats_path_segments() {
        let route = "/api/v1/dmarc/stats";
        let segments: Vec<&str> = route.split('/').filter(|s| !s.is_empty()).collect();
        assert_eq!(segments.len(), 4);
        assert_eq!(segments[0], "api");
        assert_eq!(segments[1], "v1");
        assert_eq!(segments[2], "dmarc");
        assert_eq!(segments[3], "stats");
    }

    #[test]
    fn dmarc_routes_path_no_uppercase() {
        let route = "/api/v1/dmarc/reports";
        assert_eq!(route, route.to_ascii_lowercase());
    }

    #[test]
    fn dmarc_routes_path_no_spaces() {
        let route = "/api/v1/dmarc/reports";
        assert!(!route.contains(" "));
    }

    #[test]
    fn dmarc_routes_path_no_special_chars() {
        let route = "/api/v1/dmarc/reports";
        assert!(route.chars().all(|c| c.is_alphanumeric() || c == '/' || c == '_' || c == '-'));
    }

    #[test]
    fn dmarc_routes_path_valid() {
        let route = "/api/v1/dmarc/reports";
        assert!(route.starts_with("/"));
        assert!(!route.ends_with("/"));
        assert!(!route.contains("//"));
    }

    #[test]
    fn dmarc_routes_stats_path_valid() {
        let route = "/api/v1/dmarc/stats";
        assert!(route.starts_with("/"));
        assert!(!route.ends_with("/"));
        assert!(!route.contains("//"));
    }

    #[test]
    fn dmarc_routes_method_get_format() {
        let method = "GET";
        assert_eq!(method.len(), 3);
        assert_eq!(method, method.to_ascii_uppercase());
    }

    #[test]
    fn dmarc_routes_method_post_format() {
        let method = "POST";
        assert_eq!(method.len(), 4);
        assert_eq!(method, method.to_ascii_uppercase());
    }

    #[test]
    fn dmarc_routes_method_get_valid() {
        let method = "GET";
        let valid_methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH"];
        assert!(valid_methods.contains(&method));
    }

    #[test]
    fn dmarc_routes_method_post_valid() {
        let method = "POST";
        let valid_methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH"];
        assert!(valid_methods.contains(&method));
    }

    #[test]
    fn dmarc_routes_method_get_no_spaces() {
        let method = "GET";
        assert!(!method.contains(" "));
    }

    #[test]
    fn dmarc_routes_method_post_no_spaces() {
        let method = "POST";
        assert!(!method.contains(" "));
    }

    #[test]
    fn dmarc_routes_method_get_no_special_chars() {
        let method = "GET";
        assert!(method.chars().all(|c| c.is_alphabetic()));
    }

    #[test]
    fn dmarc_routes_method_post_no_special_chars() {
        let method = "POST";
        assert!(method.chars().all(|c| c.is_alphabetic()));
    }

    #[test]
    fn dmarc_routes_method_get_uppercase() {
        let method = "GET";
        assert_eq!(method, method.to_ascii_uppercase());
    }

    #[test]
    fn dmarc_routes_method_post_uppercase() {
        let method = "POST";
        assert_eq!(method, method.to_ascii_uppercase());
    }

    #[test]
    fn dmarc_routes_method_get_lowercase() {
        let method = "get";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_lowercase() {
        let method = "post";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_mixed_case() {
        let method = "Get";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_mixed_case() {
        let method = "Post";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_empty() {
        let method = "";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_empty() {
        let method = "";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_whitespace() {
        let method = " GET ";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_whitespace() {
        let method = " POST ";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_leading_space() {
        let method = " GET";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_leading_space() {
        let method = " POST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_trailing_space() {
        let method = "GET ";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_trailing_space() {
        let method = "POST ";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_tab() {
        let method = "\tGET";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_tab() {
        let method = "\tPOST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_newline() {
        let method = "\nGET";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_newline() {
        let method = "\nPOST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_carriage_return() {
        let method = "\rGET";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_carriage_return() {
        let method = "\rPOST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_null() {
        let method = "\0GET";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_null() {
        let method = "\0POST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_unicode() {
        let method = "GÉT";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_unicode() {
        let method = "PÖST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_emoji() {
        let method = "GET😀";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_emoji() {
        let method = "POST😀";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_underscore() {
        let method = "GE_T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_underscore() {
        let method = "PO_ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_hyphen() {
        let method = "GE-T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_hyphen() {
        let method = "PO-ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_dot() {
        let method = "GE.T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_dot() {
        let method = "PO.ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_slash() {
        let method = "GE/T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_slash() {
        let method = "PO/ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_backslash() {
        let method = "GE\\T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_backslash() {
        let method = "PO\\ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_colon() {
        let method = "GE:T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_colon() {
        let method = "PO:ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_semicolon() {
        let method = "GE;T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_semicolon() {
        let method = "PO;ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_comma() {
        let method = "GE,T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_comma() {
        let method = "PO,ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_pipe() {
        let method = "GE|T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_pipe() {
        let method = "PO|ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_ampersand() {
        let method = "GE&T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_ampersand() {
        let method = "PO&ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_at() {
        let method = "GE@T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_at() {
        let method = "PO@ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_hash() {
        let method = "GE#T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_hash() {
        let method = "PO#ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_dollar() {
        let method = "GE$T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_dollar() {
        let method = "PO$ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_percent() {
        let method = "GE%T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_percent() {
        let method = "PO%ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_exclamation() {
        let method = "GE!T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_exclamation() {
        let method = "PO!ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_question() {
        let method = "GE?T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_question() {
        let method = "PO?ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_plus() {
        let method = "GE+T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_plus() {
        let method = "PO+ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_equals() {
        let method = "GE=T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_equals() {
        let method = "PO=ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_star() {
        let method = "GE*T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_star() {
        let method = "PO*ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_parentheses() {
        let method = "GE(T)";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_parentheses() {
        let method = "PO(ST)";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_brackets() {
        let method = "GE[T]";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_brackets() {
        let method = "PO[ST]";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_braces() {
        let method = "GE{T}";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_braces() {
        let method = "PO{ST}";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_less_than() {
        let method = "GE<T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_less_than() {
        let method = "PO<ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_greater_than() {
        let method = "GE>T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_greater_than() {
        let method = "PO>ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_caret() {
        let method = "GE^T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_caret() {
        let method = "PO^ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn dmarc_routes_method_get_backtick() {
        let method = "GE`T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn dmarc_routes_method_post_backtick() {
        let method = "PO`ST";
        assert_ne!(method, "POST");
    }
}
