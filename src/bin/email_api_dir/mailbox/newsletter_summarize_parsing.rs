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
    fn extract_completion_content_string() {
        let payload = serde_json::json!({
            "choices": [{"message": {"content": "Hello World"}}]
        });
        assert_eq!(extract_completion_content(&payload), Some("Hello World".to_string()));
    }

    #[test]
    fn extract_completion_content_array() {
        let payload = serde_json::json!({
            "choices": [{"message": {"content": [{"text": "Part 1"}, {"text": "Part 2"}]}}]
        });
        assert_eq!(extract_completion_content(&payload), Some("Part 1\nPart 2".to_string()));
    }

    #[test]
    fn extract_completion_content_empty() {
        let payload = serde_json::json!({
            "choices": [{"message": {"content": ""}}]
        });
        assert_eq!(extract_completion_content(&payload), None);
    }

    #[test]
    fn extract_completion_content_missing() {
        let payload = serde_json::json!({"choices": []});
        assert_eq!(extract_completion_content(&payload), None);
    }

    #[test]
    fn extract_json_object_valid() {
        let text = r#"{"key": "value"}"#;
        let result = extract_json_object(text).unwrap();
        assert_eq!(result["key"], "value");
    }

    #[test]
    fn extract_json_object_with_surrounding_text() {
        let text = r#"Here is the JSON: {"key": "value"} and more text"#;
        let result = extract_json_object(text).unwrap();
        assert_eq!(result["key"], "value");
    }

    #[test]
    fn extract_json_object_invalid() {
        let text = "not json at all";
        assert!(extract_json_object(text).is_none());
    }

    #[test]
    fn extract_http_urls_single() {
        let text = "Check https://example.com for more";
        let urls = extract_http_urls(text, 10);
        assert_eq!(urls.len(), 1);
        assert!(urls[0].contains("example.com"));
    }

    #[test]
    fn extract_http_urls_multiple() {
        let text = "Visit https://a.com and https://b.com";
        let urls = extract_http_urls(text, 10);
        assert_eq!(urls.len(), 2);
    }

    #[test]
    fn extract_http_urls_respects_max() {
        let text = "Visit https://a.com https://b.com https://c.com";
        let urls = extract_http_urls(text, 2);
        assert_eq!(urls.len(), 2);
    }

    #[test]
    fn extract_http_urls_dedup() {
        let text = "Visit https://a.com and https://a.com again";
        let urls = extract_http_urls(text, 10);
        assert_eq!(urls.len(), 1);
    }

    #[test]
    fn extract_http_urls_empty() {
        let text = "no links here";
        let urls = extract_http_urls(text, 10);
        assert!(urls.is_empty());
    }

    #[test]
    fn build_summary_from_article_digests_valid() {
        let parsed = serde_json::json!({
            "articleDigests": [
                {"url": "https://a.com", "title": "Title A", "summary": "Digest A"},
                {"url": "https://b.com", "title": "Title B", "summary": "Digest B"}
            ]
        });
        let result = build_summary_from_article_digests(&Some(parsed)).unwrap();
        assert!(result.contains("Title A"));
        assert!(result.contains("Digest A"));
        assert!(result.contains("Sources:"));
    }

    #[test]
    fn build_summary_from_article_digests_empty() {
        let parsed = serde_json::json!({"articleDigests": []});
        assert!(build_summary_from_article_digests(&Some(parsed)).is_none());
    }

    #[test]
    fn build_summary_from_article_digests_none() {
        assert!(build_summary_from_article_digests(&None).is_none());
    }

    #[test]
    fn ensure_sources_block_empty_summary() {
        let result = ensure_sources_block("", &[("Name".to_string(), "https://a.com".to_string())]);
        assert_eq!(result, "");
    }

    #[test]
    fn ensure_sources_block_no_links() {
        let result = ensure_sources_block("Summary", &[]);
        assert_eq!(result, "Summary");
    }

    #[test]
    fn ensure_sources_block_adds_sources() {
        let result = ensure_sources_block("Summary", &[("Name".to_string(), "https://a.com".to_string())]);
        assert!(result.contains("Sources:"));
        assert!(result.contains("Name"));
    }

    #[test]
    fn ensure_sources_block_already_has_sources() {
        let summary = "Summary\n\nSources:\n1. Existing — https://existing.com";
        let result = ensure_sources_block(summary, &[("New".to_string(), "https://new.com".to_string())]);
        assert_eq!(result, summary);
    }

    #[test]
    fn ensure_sources_block_limits_to_six() {
        let links: Vec<(String, String)> = (0..10).map(|i| (format!("Name{}", i), format!("https://{}.com", i))).collect();
        let result = ensure_sources_block("Summary", &links);
        let sources_lines = result.lines().filter(|l| l.contains("—")).count();
        assert_eq!(sources_lines, 6);
    }
}
