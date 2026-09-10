use super::*;
use std::collections::HashSet;

pub(crate) fn extract_completion_content(payload: &serde_json::Value) -> Option<String> {
    let content = payload
        .get("choices")?
        .as_array()?
        .first()?
        .get("message")?
        .get("content")?;

    if let Some(text) = content.as_str() {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let arr = content.as_array()?;
    let combined = arr
        .iter()
        .filter_map(|part| part.get("text").and_then(|v| v.as_str()))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();

    if combined.is_empty() {
        None
    } else {
        Some(combined)
    }
}

pub(crate) fn extract_json_object(text: &str) -> Option<serde_json::Value> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        return Some(v);
    }

    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end <= start {
        return None;
    }

    serde_json::from_str::<serde_json::Value>(&text[start..=end]).ok()
}

pub(crate) fn extract_http_urls(text: &str, max_urls: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut idx = 0usize;

    while idx < text.len() {
        let next_http = text[idx..].find("http://");
        let next_https = text[idx..].find("https://");
        let rel = match (next_http, next_https) {
            (Some(a), Some(b)) => Some(std::cmp::min(a, b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        let rel = match rel {
            Some(v) => v,
            None => break,
        };

        let start = idx + rel;
        let tail = &text[start..];
        let end_rel = tail
            .find(|c: char| c.is_whitespace() || c == ')' || c == ']' || c == '>' || c == '"')
            .unwrap_or(tail.len());

        let url = tail[..end_rel]
            .trim_end_matches('.')
            .trim_end_matches(',')
            .trim_end_matches(';');

        if let Some(norm) = normalize_url(Some(url)) {
            if seen.insert(norm.clone()) {
                out.push(norm);
                if out.len() >= max_urls {
                    break;
                }
            }
        }

        idx = start + end_rel;
    }

    out
}

pub(crate) fn build_summary_from_article_digests(
    parsed_json: &Option<serde_json::Value>,
) -> Option<String> {
    let digests = parsed_json
        .as_ref()
        .and_then(|v| v.get("articleDigests"))
        .and_then(|v| v.as_array())?;

    let rows: Vec<(String, String, String)> = digests
        .iter()
        .filter_map(|entry| {
            let url = entry
                .get("url")
                .and_then(|v| v.as_str())
                .and_then(|v| normalize_url(Some(v)))?;
            let title = entry
                .get("title")
                .and_then(|v| v.as_str())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "Article".to_string());
            let digest = entry
                .get("summary")
                .and_then(|v| v.as_str())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())?;
            Some((title, url, digest))
        })
        .take(5)
        .collect();

    if rows.is_empty() {
        return None;
    }

    let body = rows
        .iter()
        .enumerate()
        .map(|(idx, (title, _url, digest))| format!("{}. {} — {}", idx + 1, title, digest))
        .collect::<Vec<_>>()
        .join("\n");

    let sources = rows
        .iter()
        .enumerate()
        .map(|(idx, (title, url, _digest))| format!("{}. {} — {}", idx + 1, title, url))
        .collect::<Vec<_>>()
        .join("\n");

    Some(format!("{}\n\nSources:\n{}", body, sources))
}

pub(crate) fn ensure_sources_block(summary: &str, curated_links: &[(String, String)]) -> String {
    let trimmed = summary.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if curated_links.is_empty() {
        return trimmed.to_string();
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("\nsources:") || lower.starts_with("sources:") {
        return trimmed.to_string();
    }

    let sources = curated_links
        .iter()
        .take(6)
        .enumerate()
        .map(|(idx, (name, url))| format!("{}. {} — {}", idx + 1, name, url))
        .collect::<Vec<_>>()
        .join("\n");

    format!("{}\n\nSources:\n{}", trimmed, sources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_completion_content_text_string() {
        let payload = serde_json::json!({
            "choices": [{"message": {"content": "Hello world"}}]
        });
        assert_eq!(extract_completion_content(&payload), Some("Hello world".to_string()));
    }

    #[test]
    fn extract_completion_content_array() {
        let payload = serde_json::json!({
            "choices": [{"message": {"content": [{"text": "Part 1"}, {"text": "Part 2"}]}}]
        });
        assert_eq!(extract_completion_content(&payload), Some("Part 1\nPart 2".to_string()));
    }

    #[test]
    fn extract_completion_content_empty_returns_none() {
        let payload = serde_json::json!({
            "choices": [{"message": {"content": ""}}]
        });
        assert_eq!(extract_completion_content(&payload), None);
    }

    #[test]
    fn extract_json_object_valid() {
        let result = extract_json_object(r#"{"key": "value"}"#);
        assert!(result.is_some());
        assert_eq!(result.unwrap()["key"], "value");
    }

    #[test]
    fn extract_json_object_with_noise() {
        let result = extract_json_object(r#"Some text before {"key": 42} and after"#);
        assert!(result.is_some());
        assert_eq!(result.unwrap()["key"], 42);
    }

    #[test]
    fn extract_json_object_invalid() {
        assert!(extract_json_object("not json at all").is_none());
        assert!(extract_json_object("{invalid}").is_none());
    }

    #[test]
    fn extract_http_urls_basic() {
        let text = "Check https://example.com and http://test.org";
        let urls = extract_http_urls(text, 10);
        assert!(urls.contains(&"https://example.com".to_string()));
        assert!(urls.contains(&"http://test.org".to_string()));
    }

    #[test]
    fn extract_http_urls_respects_max() {
        let text = "https://a.com https://b.com https://c.com";
        let urls = extract_http_urls(text, 2);
        assert_eq!(urls.len(), 2);
    }

    #[test]
    fn extract_http_urls_deduplicates() {
        let text = "https://example.com https://example.com";
        let urls = extract_http_urls(text, 10);
        assert_eq!(urls.len(), 1);
    }

    #[test]
    fn extract_http_urls_strips_trailing_punctuation() {
        let text = "Visit https://example.com. Then go.";
        let urls = extract_http_urls(text, 10);
        assert_eq!(urls[0], "https://example.com");
    }

    #[test]
    fn extract_http_urls_empty_text() {
        assert!(extract_http_urls("", 10).is_empty());
    }

    #[test]
    fn build_summary_from_article_digests_valid() {
        let parsed = serde_json::json!({
            "articleDigests": [
                {"url": "https://a.com", "title": "T1", "summary": "S1"},
                {"url": "https://b.com", "title": "T2", "summary": "S2"}
            ]
        });
        let result = build_summary_from_article_digests(&Some(parsed));
        assert!(result.is_some());
        let text = result.unwrap();
        assert!(text.contains("T1 — S1"));
        assert!(text.contains("T2 — S2"));
        assert!(text.contains("Sources:"));
    }

    #[test]
    fn build_summary_from_article_digests_empty() {
        let parsed = serde_json::json!({"articleDigests": []});
        assert_eq!(build_summary_from_article_digests(&Some(parsed)), None);
    }

    #[test]
    fn build_summary_from_article_digests_none() {
        assert_eq!(build_summary_from_article_digests(&None), None);
    }

    #[test]
    fn ensure_sources_block_empty_summary() {
        assert_eq!(ensure_sources_block("", &[("A".into(), "https://a.com".into())]), "");
    }

    #[test]
    fn ensure_sources_block_no_links() {
        assert_eq!(ensure_sources_block("Summary", &[]), "Summary");
    }

    #[test]
    fn ensure_sources_block_adds_sources() {
        let result = ensure_sources_block("Summary", &[("A".into(), "https://a.com".into())]);
        assert!(result.contains("Sources:"));
        assert!(result.contains("1. A — https://a.com"));
    }

    #[test]
    fn ensure_sources_block_preserves_existing_sources() {
        let result = ensure_sources_block("Summary\n\nSources:\n1. X", &[("A".into(), "https://a.com".into())]);
        assert!(!result.contains("1. A — https://a.com"));
    }
}
