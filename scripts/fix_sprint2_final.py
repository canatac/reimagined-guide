#!/usr/bin/env python3
# fix_sprint2_final.py — fix remaining compilation errors

import re

# --- 1. Add env_bool + dns_txt_lookup to monitoring_handlers.rs ---
monitoring_path = "/root/reimagined-guide/src/bin/email_api_dir/monitoring_handlers.rs"
helpers = '''
// ─── Shared helpers (used by admin_ops_handlers too via super::*) ─────────────

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
'''
with open(monitoring_path, "a") as f:
    f.write(helpers)
print(f"monitoring_handlers.rs: appended env_bool + dns_txt_lookup")

# --- 2. Fix ExternalMessagesQuery fields in admin_ops_handlers.rs ---
admin_path = "/root/reimagined-guide/src/bin/email_api_dir/admin_ops_handlers.rs"
content = open(admin_path).read()
# Make struct fields pub
content = re.sub(
    r'(pub\(crate\) struct ExternalMessagesQuery \{[^}]+\})',
    lambda m: re.sub(r'\n    (\w)', r'\n    pub(crate) \1', m.group(0)),
    content
)
# Remove rogue "pub(crate) async fn main" if present
content = re.sub(
    r'\n#\[actix_web::main\]\npub\(crate\) async fn main\(\)[^\n]*\n',
    '\n',
    content
)
open(admin_path, "w").write(content)
print("admin_ops_handlers.rs: ExternalMessagesQuery fields pub + async main removed")
