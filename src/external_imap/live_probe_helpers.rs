/*!
 * Helpers extracted from live_probe.rs (Cycle 48).
 */

pub fn escape_imap(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn sse_line_frame(payload: &str) -> String {
    format!("event: line\ndata: {payload}\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_imap_backslash() {
        assert_eq!(escape_imap(r"a\b"), r"a\\b");
    }

    #[test]
    fn escape_imap_double_quote() {
        assert_eq!(escape_imap(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn escape_imap_both() {
        assert_eq!(escape_imap(r#"a\b"c"#), r#"a\\b\"c"#);
    }

    #[test]
    fn escape_imap_no_special() {
        assert_eq!(escape_imap("hello world"), "hello world");
    }

    #[test]
    fn sse_line_frame_format() {
        let frame = sse_line_frame(r#"{"dir":">","text":"a1 CAPABILITY"}"#);
        assert_eq!(frame, "event: line\ndata: {\"dir\":\">\",\"text\":\"a1 CAPABILITY\"}\n\n");
    }

    #[test]
    fn sse_line_frame_empty_payload() {
        let frame = sse_line_frame("");
        assert_eq!(frame, "event: line\ndata: \n\n");
    }
}
