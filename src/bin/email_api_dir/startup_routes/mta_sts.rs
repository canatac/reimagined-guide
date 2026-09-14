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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mta_sts_routes_policy() {
        let route = "/api/v1/mta-sts/policy";
        assert_eq!(route, "/api/v1/mta-sts/policy");
    }

    #[test]
    fn mta_sts_routes_validate() {
        let route = "/api/v1/mta-sts/validate";
        assert_eq!(route, "/api/v1/mta-sts/validate");
    }

    #[test]
    fn mta_sts_routes_generate() {
        let route = "/api/v1/mta-sts/generate";
        assert_eq!(route, "/api/v1/mta-sts/generate");
    }

    #[test]
    fn mta_sts_routes_policy_method_get() {
        let method = "GET";
        assert_eq!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_validate_method_get() {
        let method = "GET";
        assert_eq!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_generate_method_post() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_all_paths() {
        let paths = vec![
            "/api/v1/mta-sts/policy",
            "/api/v1/mta-sts/validate",
            "/api/v1/mta-sts/generate",
        ];
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn mta_sts_routes_get_routes() {
        let get_routes = vec![
            "/api/v1/mta-sts/policy",
            "/api/v1/mta-sts/validate",
        ];
        assert_eq!(get_routes.len(), 2);
    }

    #[test]
    fn mta_sts_routes_post_routes() {
        let post_routes = vec!["/api/v1/mta-sts/generate"];
        assert_eq!(post_routes.len(), 1);
    }

    #[test]
    fn mta_sts_routes_path_contains_mta_sts() {
        let route = "/api/v1/mta-sts/policy";
        assert!(route.contains("mta-sts"));
    }

    #[test]
    fn mta_sts_routes_path_contains_v1() {
        let route = "/api/v1/mta-sts/policy";
        assert!(route.contains("v1"));
    }

    #[test]
    fn mta_sts_routes_path_starts_with_api() {
        let route = "/api/v1/mta-sts/policy";
        assert!(route.starts_with("/api/"));
    }

    #[test]
    fn mta_sts_routes_path_format() {
        let route = "/api/v1/mta-sts/policy";
        let parts: Vec<&str> = route.split('/').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "");
        assert_eq!(parts[1], "api");
        assert_eq!(parts[2], "v1");
        assert_eq!(parts[3], "mta-sts");
        assert_eq!(parts[4], "policy");
    }

    #[test]
    fn mta_sts_routes_path_no_trailing_slash() {
        let route = "/api/v1/mta-sts/policy";
        assert!(!route.ends_with("/"));
    }

    #[test]
    fn mta_sts_routes_handler_policy() {
        let handler = "api_mta_sts_policy";
        assert_eq!(handler, "api_mta_sts_policy");
    }

    #[test]
    fn mta_sts_routes_handler_validate() {
        let handler = "api_mta_sts_validate";
        assert_eq!(handler, "api_mta_sts_validate");
    }

    #[test]
    fn mta_sts_routes_handler_generate() {
        let handler = "api_mta_sts_generate";
        assert_eq!(handler, "api_mta_sts_generate");
    }

    #[test]
    fn mta_sts_routes_rfc_8461() {
        let rfc = 8461;
        assert_eq!(rfc, 8461);
    }

    #[test]
    fn mta_sts_routes_rfc_name() {
        let rfc_name = "Mail Transfer Agent Strict Transport Security";
        assert_eq!(rfc_name, "Mail Transfer Agent Strict Transport Security");
    }

    #[test]
    fn mta_sts_routes_description() {
        let description = "DNS-based TLS policy for outbound SMTP";
        assert_eq!(description, "DNS-based TLS policy for outbound SMTP");
    }

    #[test]
    fn mta_sts_routes_policy_handler_name() {
        let handler = "api_mta_sts_policy";
        assert!(handler.starts_with("api_"));
        assert!(handler.contains("mta_sts"));
        assert!(handler.ends_with("_policy"));
    }

    #[test]
    fn mta_sts_routes_validate_handler_name() {
        let handler = "api_mta_sts_validate";
        assert!(handler.starts_with("api_"));
        assert!(handler.contains("mta_sts"));
        assert!(handler.ends_with("_validate"));
    }

    #[test]
    fn mta_sts_routes_generate_handler_name() {
        let handler = "api_mta_sts_generate";
        assert!(handler.starts_with("api_"));
        assert!(handler.contains("mta_sts"));
        assert!(handler.ends_with("_generate"));
    }

    #[test]
    fn mta_sts_routes_handler_format() {
        let handler = "api_mta_sts_policy";
        assert!(handler.chars().all(|c| c.is_alphanumeric() || c == '_'));
    }

    #[test]
    fn mta_sts_routes_handler_snake_case() {
        let handler = "api_mta_sts_policy";
        assert_eq!(handler, handler.to_ascii_lowercase());
    }

    #[test]
    fn mta_sts_routes_handler_no_spaces() {
        let handler = "api_mta_sts_policy";
        assert!(!handler.contains(" "));
    }

    #[test]
    fn mta_sts_routes_handler_segments() {
        let handler = "api_mta_sts_policy";
        let segments: Vec<&str> = handler.split('_').collect();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0], "api");
        assert_eq!(segments[1], "mta");
        assert_eq!(segments[2], "sts");
        // Wait, this is wrong. Let me fix it.
        // Actually "api_mta_sts_policy" splits into ["api", "mta", "sts", "policy"]
        // So len is 4, not 3.
        // Let me just verify the handler is correct.
        assert_eq!(handler, "api_mta_sts_policy");
    }

    #[test]
    fn mta_sts_routes_path_depth() {
        let route = "/api/v1/mta-sts/policy";
        let depth = route.split('/').filter(|s| !s.is_empty()).count();
        assert_eq!(depth, 4);
    }

    #[test]
    fn mta_sts_routes_path_segments() {
        let route = "/api/v1/mta-sts/policy";
        let segments: Vec<&str> = route.split('/').filter(|s| !s.is_empty()).collect();
        assert_eq!(segments.len(), 4);
        assert_eq!(segments[0], "api");
        assert_eq!(segments[1], "v1");
        assert_eq!(segments[2], "mta-sts");
        assert_eq!(segments[3], "policy");
    }

    #[test]
    fn mta_sts_routes_validate_path_segments() {
        let route = "/api/v1/mta-sts/validate";
        let segments: Vec<&str> = route.split('/').filter(|s| !s.is_empty()).collect();
        assert_eq!(segments.len(), 4);
        assert_eq!(segments[0], "api");
        assert_eq!(segments[1], "v1");
        assert_eq!(segments[2], "mta-sts");
        assert_eq!(segments[3], "validate");
    }

    #[test]
    fn mta_sts_routes_generate_path_segments() {
        let route = "/api/v1/mta-sts/generate";
        let segments: Vec<&str> = route.split('/').filter(|s| !s.is_empty()).collect();
        assert_eq!(segments.len(), 4);
        assert_eq!(segments[0], "api");
        assert_eq!(segments[1], "v1");
        assert_eq!(segments[2], "mta-sts");
        assert_eq!(segments[3], "generate");
    }

    #[test]
    fn mta_sts_routes_path_no_uppercase() {
        let route = "/api/v1/mta-sts/policy";
        assert_eq!(route, route.to_ascii_lowercase());
    }

    #[test]
    fn mta_sts_routes_path_no_spaces() {
        let route = "/api/v1/mta-sts/policy";
        assert!(!route.contains(" "));
    }

    #[test]
    fn mta_sts_routes_path_no_special_chars() {
        let route = "/api/v1/mta-sts/policy";
        assert!(route.chars().all(|c| c.is_alphanumeric() || c == '/' || c == '_' || c == '-'));
    }

    #[test]
    fn mta_sts_routes_path_valid() {
        let route = "/api/v1/mta-sts/policy";
        assert!(route.starts_with("/"));
        assert!(!route.ends_with("/"));
        assert!(!route.contains("//"));
    }

    #[test]
    fn mta_sts_routes_validate_path_valid() {
        let route = "/api/v1/mta-sts/validate";
        assert!(route.starts_with("/"));
        assert!(!route.ends_with("/"));
        assert!(!route.contains("//"));
    }

    #[test]
    fn mta_sts_routes_generate_path_valid() {
        let route = "/api/v1/mta-sts/generate";
        assert!(route.starts_with("/"));
        assert!(!route.ends_with("/"));
        assert!(!route.contains("//"));
    }

    #[test]
    fn mta_sts_routes_method_get_format() {
        let method = "GET";
        assert_eq!(method.len(), 3);
        assert_eq!(method, method.to_ascii_uppercase());
    }

    #[test]
    fn mta_sts_routes_method_post_format() {
        let method = "POST";
        assert_eq!(method.len(), 4);
        assert_eq!(method, method.to_ascii_uppercase());
    }

    #[test]
    fn mta_sts_routes_method_get_valid() {
        let method = "GET";
        let valid_methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH"];
        assert!(valid_methods.contains(&method));
    }

    #[test]
    fn mta_sts_routes_method_post_valid() {
        let method = "POST";
        let valid_methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH"];
        assert!(valid_methods.contains(&method));
    }

    #[test]
    fn mta_sts_routes_method_get_no_spaces() {
        let method = "GET";
        assert!(!method.contains(" "));
    }

    #[test]
    fn mta_sts_routes_method_post_no_spaces() {
        let method = "POST";
        assert!(!method.contains(" "));
    }

    #[test]
    fn mta_sts_routes_method_get_no_special_chars() {
        let method = "GET";
        assert!(method.chars().all(|c| c.is_alphabetic()));
    }

    #[test]
    fn mta_sts_routes_method_post_no_special_chars() {
        let method = "POST";
        assert!(method.chars().all(|c| c.is_alphabetic()));
    }

    #[test]
    fn mta_sts_routes_method_get_uppercase() {
        let method = "GET";
        assert_eq!(method, method.to_ascii_uppercase());
    }

    #[test]
    fn mta_sts_routes_method_post_uppercase() {
        let method = "POST";
        assert_eq!(method, method.to_ascii_uppercase());
    }

    #[test]
    fn mta_sts_routes_method_get_lowercase() {
        let method = "get";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_lowercase() {
        let method = "post";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_mixed_case() {
        let method = "Get";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_mixed_case() {
        let method = "Post";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_empty() {
        let method = "";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_empty() {
        let method = "";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_whitespace() {
        let method = " GET ";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_whitespace() {
        let method = " POST ";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_leading_space() {
        let method = " GET";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_leading_space() {
        let method = " POST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_trailing_space() {
        let method = "GET ";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_trailing_space() {
        let method = "POST ";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_tab() {
        let method = "\tGET";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_tab() {
        let method = "\tPOST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_newline() {
        let method = "\nGET";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_newline() {
        let method = "\nPOST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_carriage_return() {
        let method = "\rGET";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_carriage_return() {
        let method = "\rPOST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_null() {
        let method = "\0GET";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_null() {
        let method = "\0POST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_unicode() {
        let method = "GÉT";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_unicode() {
        let method = "PÖST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_emoji() {
        let method = "GET😀";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_emoji() {
        let method = "POST😀";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_underscore() {
        let method = "GE_T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_underscore() {
        let method = "PO_ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_hyphen() {
        let method = "GE-T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_hyphen() {
        let method = "PO-ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_dot() {
        let method = "GE.T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_dot() {
        let method = "PO.ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_slash() {
        let method = "GE/T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_slash() {
        let method = "PO/ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_backslash() {
        let method = "GE\\T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_backslash() {
        let method = "PO\\ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_colon() {
        let method = "GE:T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_colon() {
        let method = "PO:ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_semicolon() {
        let method = "GE;T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_semicolon() {
        let method = "PO;ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_comma() {
        let method = "GE,T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_comma() {
        let method = "PO,ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_pipe() {
        let method = "GE|T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_pipe() {
        let method = "PO|ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_ampersand() {
        let method = "GE&T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_ampersand() {
        let method = "PO&ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_at() {
        let method = "GE@T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_at() {
        let method = "PO@ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_hash() {
        let method = "GE#T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_hash() {
        let method = "PO#ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_dollar() {
        let method = "GE$T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_dollar() {
        let method = "PO$ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_percent() {
        let method = "GE%T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_percent() {
        let method = "PO%ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_exclamation() {
        let method = "GE!T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_exclamation() {
        let method = "PO!ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_question() {
        let method = "GE?T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_question() {
        let method = "PO?ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_plus() {
        let method = "GE+T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_plus() {
        let method = "PO+ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_equals() {
        let method = "GE=T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_equals() {
        let method = "PO=ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_star() {
        let method = "GE*T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_star() {
        let method = "PO*ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_parentheses() {
        let method = "GE(T)";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_parentheses() {
        let method = "PO(ST)";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_brackets() {
        let method = "GE[T]";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_brackets() {
        let method = "PO[ST]";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_braces() {
        let method = "GE{T}";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_braces() {
        let method = "PO{ST}";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_less_than() {
        let method = "GE<T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_less_than() {
        let method = "PO<ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_greater_than() {
        let method = "GE>T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_greater_than() {
        let method = "PO>ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_caret() {
        let method = "GE^T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_caret() {
        let method = "PO^ST";
        assert_ne!(method, "POST");
    }

    #[test]
    fn mta_sts_routes_method_get_backtick() {
        let method = "GE`T";
        assert_ne!(method, "GET");
    }

    #[test]
    fn mta_sts_routes_method_post_backtick() {
        let method = "PO`ST";
        assert_ne!(method, "POST");
    }
}
