use super::*;
use std::collections::HashSet;

pub(crate) fn normalize_plain_text(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) fn truncate_chars(raw: &str, max_chars: usize) -> String {
    if raw.chars().count() <= max_chars {
        return raw.to_string();
    }
    raw.chars().take(max_chars).collect::<String>()
}

pub(crate) fn is_html_payload(content_type: &str, raw_body: &str) -> bool {
    content_type.contains("text/html") || raw_body.to_ascii_lowercase().contains("<html")
}

fn normalize_discovered_link(base_url: &str, candidate: &str) -> Option<String> {
    let raw = candidate
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .replace("&amp;", "&");
    if raw.is_empty()
        || raw.starts_with('#')
        || raw.starts_with("mailto:")
        || raw.starts_with("javascript:")
    {
        return None;
    }

    if raw.starts_with("http://") || raw.starts_with("https://") {
        return Some(raw);
    }

    let base = reqwest::Url::parse(base_url).ok()?;
    let joined = base.join(&raw).ok()?;
    let scheme = joined.scheme();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    Some(joined.to_string())
}

fn looks_like_content_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    if lower.contains("/login")
        || lower.contains("/signup")
        || lower.contains("/register")
        || lower.contains("/privacy")
        || lower.contains("/terms")
        || lower.contains("/contact")
        || lower.contains("/about")
    {
        return false;
    }

    if lower.ends_with(".css")
        || lower.ends_with(".js")
        || lower.ends_with(".png")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".svg")
        || lower.ends_with(".webp")
        || lower.ends_with(".gif")
        || lower.ends_with(".ico")
    {
        return false;
    }

    true
}

pub(crate) fn extract_html_links(base_url: &str, html: &str, max_links: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let lower = html.to_ascii_lowercase();
    let mut idx = 0usize;

    while idx < lower.len() {
        let rel = match lower[idx..].find("href=") {
            Some(v) => v,
            None => break,
        };

        let href_pos = idx + rel;
        let value_start = href_pos + 5;
        if value_start >= html.len() {
            break;
        }

        let bytes = html.as_bytes();
        let quote = bytes[value_start] as char;
        let (value, next_idx) = if quote == '"' || quote == '\'' {
            let start = value_start + 1;
            let rem = &html[start..];
            match rem.find(quote) {
                Some(end_rel) => (&html[start..start + end_rel], start + end_rel + 1),
                None => ("", value_start + 1),
            }
        } else {
            let rem = &html[value_start..];
            let end_rel = rem
                .find(|c: char| c.is_whitespace() || c == '>')
                .unwrap_or(rem.len());
            (&html[value_start..value_start + end_rel], value_start + end_rel)
        };

        if let Some(abs) = normalize_discovered_link(base_url, value) {
            if looks_like_content_url(&abs) && seen.insert(abs.clone()) {
                out.push(abs);
                if out.len() >= max_links {
                    break;
                }
            }
        }

        idx = next_idx;
    }

    out
}

fn is_homepage_url(url: &str) -> bool {
    match reqwest::Url::parse(url) {
        Ok(parsed) => {
            let path = parsed.path().trim();
            path.is_empty() || path == "/"
        }
        Err(_) => false,
    }
}

fn has_specific_path(url: &str) -> bool {
    match reqwest::Url::parse(url) {
        Ok(parsed) => {
            let path = parsed.path().trim();
            !path.is_empty() && path != "/"
        }
        Err(_) => false,
    }
}

fn same_site(a: &str, b: &str) -> bool {
    let host_a = reqwest::Url::parse(a)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()));
    let host_b = reqwest::Url::parse(b)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()));

    match (host_a, host_b) {
        (Some(ha), Some(hb)) => {
            ha == hb || ha.ends_with(&format!(".{}", hb)) || hb.ends_with(&format!(".{}", ha))
        }
        _ => false,
    }
}

pub(crate) fn should_update_source_url(previous: &str, candidate: &str) -> bool {
    if previous == candidate {
        return false;
    }
    if !same_site(previous, candidate) {
        return false;
    }
    is_homepage_url(previous) && has_specific_path(candidate)
}

pub(crate) fn discover_section_urls(base_url: &str) -> Vec<String> {
    let base = match reqwest::Url::parse(base_url) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let candidates = [
        "/blog",
        "/blogs",
        "/insights",
        "/news",
        "/articles",
        "/publications",
        "/technology",
        "/engineering",
    ];

    for path in candidates {
        if let Ok(url) = base.join(path) {
            let s = url.to_string();
            if seen.insert(s.clone()) {
                out.push(s);
            }
        }
    }
    out
}

pub(crate) fn merge_links(target: &mut Vec<String>, incoming: Vec<String>, max_links: usize) {
    let mut seen: HashSet<String> = target.iter().cloned().collect();
    for link in incoming {
        if seen.insert(link.clone()) {
            target.push(link);
            if target.len() >= max_links {
                break;
            }
        }
    }
}
