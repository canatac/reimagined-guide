// misc helpers (env_bool, dns_txt_lookup) (cycle 15 split from mod.rs)

pub(crate) fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

pub(crate) async fn dns_txt_lookup(name: &str) -> Vec<String> {
    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
    use trust_dns_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let mut rows: Vec<String> = Vec::new();

    if let Ok(lookup) = resolver.txt_lookup(name).await {
        for txt in lookup.iter() {
            for part in txt.txt_data() {
                if let Ok(s) = std::str::from_utf8(part) {
                    rows.push(s.to_string());
                }
            }
        }
    }

    rows
}
