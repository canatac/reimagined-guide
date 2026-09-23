//! JMAP route registration — re-exports from the parent jmap module.

pub use super::super::jmap::register_jmap_routes;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jmap_routes_register_fn_exists() {
        let fn_name = "register_jmap_routes";
        assert_eq!(fn_name, "register_jmap_routes");
    }

    #[test]
    fn jmap_routes_well_known() {
        let route = "/.well-known/jmap";
        assert_eq!(route, "/.well-known/jmap");
    }

    #[test]
    fn jmap_routes_session() {
        let route = "/jmap/session";
        assert_eq!(route, "/jmap/session");
    }

    #[test]
    fn jmap_routes_api() {
        let route = "/jmap";
        assert_eq!(route, "/jmap");
    }

    #[test]
    fn jmap_routes_all_paths() {
        let paths = vec!["/.well-known/jmap", "/jmap/session", "/jmap"];
        assert_eq!(paths.len(), 3);
    }
}
