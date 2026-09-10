//! Parsing helpers pour les réponses IMAP brutes (extrait de mod.rs).

use chrono::Utc;

#[derive(Debug, Clone)]
pub(crate) struct ImapFetchedHeader {
    pub uid: u64,
    pub flags: Vec<String>,
    pub internal_date: Option<chrono::DateTime<Utc>>,
    pub date: Option<chrono::DateTime<Utc>>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub message_id: Option<String>,
}

pub(crate) fn read_line_from_stream<S: std::io::Read>(stream: &mut S) -> std::result::Result<String, String> {
    let mut buf = Vec::new();
    loop {
        let mut one = [0u8; 1];
        let n = stream
            .read(&mut one)
            .map_err(|e| format!("imap read line failed: {e}"))?;
        if n == 0 {
            break;
        }
        buf.push(one[0]);
        if one[0] == b'\n' {
            break;
        }
        if buf.len() > 16_384 {
            return Err("imap line too long".to_string());
        }
    }
    let line = String::from_utf8_lossy(&buf).trim().to_string();
    Ok(line)
}

pub(crate) fn read_until_tag_from_stream<S: std::io::Read>(
    stream: &mut S,
    tag: &str,
) -> std::result::Result<Vec<String>, String> {
    let mut lines = vec![];
    loop {
        let l = read_line_from_stream(stream)?;
        if l.is_empty() {
            break;
        }
        let done = l.starts_with(&format!("{} ", tag));
        lines.push(l);
        if done {
            break;
        }
    }
    Ok(lines)
}

pub(crate) fn parse_capabilities(lines: &[String]) -> Vec<String> {
    for l in lines {
        if let Some(rest) = l.strip_prefix("* CAPABILITY ") {
            return rest.split_whitespace().map(|s| s.to_string()).collect();
        }
    }
    vec![]
}

pub(crate) fn tag_status_ok(lines: &[String], tag: &str) -> bool {
    lines
        .iter()
        .any(|l| l.starts_with(&format!("{} OK", tag)))
}

pub(crate) fn parse_list_folders(lines: &[String]) -> Vec<String> {
    let mut out = vec![];
    for l in lines {
        if l.starts_with("* LIST") {
            let parts: Vec<&str> = l.split('"').collect();
            if let Some(name) = parts.last() {
                let candidate = name.trim();
                if !candidate.is_empty() {
                    out.push(candidate.to_string());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

pub(crate) fn escape_imap(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Format a chrono UTC date as RFC 3501 SEARCH date: "01-Jan-2026".
pub(crate) fn format_imap_date(dt: &chrono::DateTime<Utc>) -> String {
    dt.format("%d-%b-%Y").to_string()
}

pub(crate) fn parse_uid_search(lines: &[String]) -> Vec<u64> {
    for l in lines {
        if let Some(rest) = l.strip_prefix("* SEARCH") {
            return rest
                .split_whitespace()
                .filter_map(|s| s.parse::<u64>().ok())
                .collect();
        }
    }
    vec![]
}

/// Best-effort parse of `* N FETCH (…)` blocks over a flat line stream.
pub(crate) fn parse_fetch_headers(lines: &[String]) -> Vec<ImapFetchedHeader> {
    let mut out = Vec::new();

    let mut blocks: Vec<String> = Vec::new();
    let mut cur = String::new();
    for l in lines {
        if l.starts_with("* ") && l.contains(" FETCH ") && !cur.is_empty() {
            blocks.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push('\n');
        }
        cur.push_str(l);
    }
    if !cur.is_empty() {
        blocks.push(cur);
    }

    for b in blocks {
        if !b.contains(" FETCH ") {
            continue;
        }
        let uid = extract_uid(&b).unwrap_or(0);
        if uid == 0 {
            continue;
        }
        let internal_date = extract_internaldate(&b);
        let flags = extract_flags(&b);
        let (from, to, subject, date_hdr, message_id) = extract_header_fields(&b);
        out.push(ImapFetchedHeader {
            uid,
            flags,
            internal_date,
            date: date_hdr,
            from,
            to,
            subject,
            message_id,
        });
    }
    out
}

fn extract_uid(blob: &str) -> Option<u64> {
    let idx = blob.find("UID ")?;
    let rest = &blob[idx + 4..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse::<u64>().ok()
}

fn extract_internaldate(blob: &str) -> Option<chrono::DateTime<Utc>> {
    let idx = blob.find("INTERNALDATE ")?;
    let rest = &blob[idx + "INTERNALDATE ".len()..];
    let start = rest.find('"')? + 1;
    let end = start + rest[start..].find('"')?;
    let raw = &rest[start..end];
    chrono::DateTime::parse_from_str(raw, "%d-%b-%Y %H:%M:%S %z")
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn extract_flags(blob: &str) -> Vec<String> {
    let idx = match blob.find("FLAGS (") {
        Some(i) => i,
        None => return vec![],
    };
    let rest = &blob[idx + "FLAGS (".len()..];
    let end = match rest.find(')') {
        Some(i) => i,
        None => return vec![],
    };
    rest[..end]
        .split_whitespace()
        .map(|s| s.to_string())
        .collect()
}

fn extract_header_fields(blob: &str) -> HeaderFields {
    let mut from = None;
    let mut to = None;
    let mut subject = None;
    let mut date = None;
    let mut message_id = None;

    for raw_line in blob.lines() {
        let line = raw_line.trim_start();
        if let Some(v) = line.strip_prefix("From: ") {
            from = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("To: ") {
            to = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Subject: ") {
            subject = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Message-ID: ") {
            message_id = Some(v.trim().trim_matches(|c| c == '<' || c == '>').to_string());
        } else if let Some(v) = line.strip_prefix("Date: ") {
            date = chrono::DateTime::parse_from_rfc2822(v.trim())
                .ok()
                .map(|dt| dt.with_timezone(&Utc));
        }
    }

    (from, to, subject, date, message_id)
}

type HeaderFields = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<chrono::DateTime<Utc>>,
    Option<String>,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_capabilities_basic() {
        let lines = vec![
            "* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=XOAUTH2".to_string(),
            "a1 OK".to_string(),
        ];
        let caps = parse_capabilities(&lines);
        assert_eq!(caps, vec!["IMAP4rev1", "AUTH=PLAIN", "AUTH=XOAUTH2"]);
    }

    #[test]
    fn parse_capabilities_empty() {
        let lines = vec!["a1 OK".to_string()];
        let caps = parse_capabilities(&lines);
        assert!(caps.is_empty());
    }

    #[test]
    fn tag_status_ok_positive() {
        let lines = vec![
            "* CAPABILITY IMAP4rev1".to_string(),
            "a1 OK LOGIN completed".to_string(),
        ];
        assert!(tag_status_ok(&lines, "a1"));
    }

    #[test]
    fn tag_status_ok_negative() {
        let lines = vec![
            "a1 NO LOGIN failed".to_string(),
        ];
        assert!(!tag_status_ok(&lines, "a1"));
    }

    #[test]
    fn tag_status_ok_wrong_tag() {
        let lines = vec![
            "a1 OK".to_string(),
        ];
        assert!(!tag_status_ok(&lines, "a2"));
    }

    #[test]
    fn parse_list_folders_basic() {
        let lines = vec![
            "* LIST (\\HasNoChildren) \"/\" \"INBOX\"".to_string(),
            "* LIST (\\HasNoChildren) \"/\" \"Sent\"".to_string(),
            "* LIST (\\HasNoChildren) \"/\" \"Drafts\"".to_string(),
            "a3 OK".to_string(),
        ];
        let folders = parse_list_folders(&lines);
        assert_eq!(folders, vec!["Drafts", "INBOX", "Sent"]);
    }

    #[test]
    fn parse_list_folders_empty() {
        let lines = vec!["a3 OK".to_string()];
        let folders = parse_list_folders(&lines);
        assert!(folders.is_empty());
    }

    #[test]
    fn parse_list_folders_dedup() {
        let lines = vec![
            "* LIST (\\HasNoChildren) \"/\" \"INBOX\"".to_string(),
            "* LIST (\\HasNoChildren) \"/\" \"INBOX\"".to_string(),
        ];
        let folders = parse_list_folders(&lines);
        assert_eq!(folders, vec!["INBOX"]);
    }

    #[test]
    fn escape_imap_backslash() {
        assert_eq!(escape_imap(r"a\b"), r"a\\b");
    }

    #[test]
    fn escape_imap_quote() {
        assert_eq!(escape_imap(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn escape_imap_no_special() {
        assert_eq!(escape_imap("hello"), "hello");
    }

    #[test]
    fn format_imap_date() {
        let dt = chrono::DateTime::parse_from_rfc3339("2026-01-15T10:30:00Z").unwrap();
        let formatted = format_imap_date(&dt);
        assert_eq!(formatted, "15-Jan-2026");
    }

    #[test]
    fn parse_uid_search_basic() {
        let lines = vec![
            "* SEARCH 1 2 3 42".to_string(),
            "a5 OK".to_string(),
        ];
        let uids = parse_uid_search(&lines);
        assert_eq!(uids, vec![1, 2, 3, 42]);
    }

    #[test]
    fn parse_uid_search_empty() {
        let lines = vec![
            "* SEARCH".to_string(),
            "a5 OK".to_string(),
        ];
        let uids = parse_uid_search(&lines);
        assert!(uids.is_empty());
    }

    #[test]
    fn parse_uid_search_no_match() {
        let lines = vec!["a5 OK".to_string()];
        let uids = parse_uid_search(&lines);
        assert!(uids.is_empty());
    }

    #[test]
    fn imap_fetched_header_creation() {
        let header = ImapFetchedHeader {
            uid: 42,
            flags: vec!["\\Seen".to_string()],
            internal_date: None,
            date: None,
            from: Some("a@b.com".to_string()),
            to: Some("c@d.com".to_string()),
            subject: Some("Test".to_string()),
            message_id: Some("msg-123".to_string()),
        };
        assert_eq!(header.uid, 42);
        assert_eq!(header.flags, vec!["\\Seen".to_string()]);
        assert_eq!(header.from, Some("a@b.com".to_string()));
    }
}
