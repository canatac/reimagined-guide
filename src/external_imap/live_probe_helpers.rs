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
        assert_eq!(escape_imap("path\\to"), "path\\\\to");
    }

    #[test]
    fn escape_imap_double_quote() {
        assert_eq!(escape_imap(r#"say "hello""#), "say \\\\\"hello\\\\\"");
    }

    #[test]
    fn escape_imap_empty() {
        assert_eq!(escape_imap(""), "");
    }

    #[test]
    fn escape_imap_no_special() {
        assert_eq!(escape_imap("simple"), "simple");
    }

    #[test]
    fn sse_line_frame_format() {
        let frame = sse_line_frame("test");
        assert_eq!(frame, "event: line\ndata: test\n\n");
    }

    #[test]
    fn sse_line_frame_with_json() {
        let frame = sse_line_frame(r#"{"key":"val"}"#);
        assert_eq!(frame, "event: line\ndata: {\"key\":\"val\"}\n\n");
    }
}
