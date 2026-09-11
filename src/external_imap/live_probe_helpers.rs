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

    // --- escape_imap ---

    #[test]
    fn test_escape_imap_no_special_chars() {
        assert_eq!(escape_imap("hello"), "hello");
    }

    #[test]
    fn test_escape_imap_backslash() {
        assert_eq!(escape_imap("a\\b"), "a\\\\b");
    }

    #[test]
    fn test_escape_imap_double_quote() {
        assert_eq!(escape_imap("a\"b"), "a\\\"b");
    }

    #[test]
    fn test_escape_imap_mixed() {
        assert_eq!(escape_imap("path\\to\"file"), "path\\\\to\\\"file");
    }

    #[test]
    fn test_escape_imap_empty() {
        assert_eq!(escape_imap(""), "");
    }

    #[test]
    fn test_escape_imap_multiple_backslashes() {
        assert_eq!(escape_imap("\\\\"), "\\\\\\\\");
    }

    #[test]
    fn test_escape_imap_multiple_quotes() {
        assert_eq!(escape_imap("\"\""), "\\\"\\\"");
    }

    // --- sse_line_frame ---

    #[test]
    fn test_sse_line_frame_basic() {
        assert_eq!(sse_line_frame("hello"), "event: line\ndata: hello\n\n");
    }

    #[test]
    fn test_sse_line_frame_empty() {
        assert_eq!(sse_line_frame(""), "event: line\ndata: \n\n");
    }

    #[test]
    fn test_sse_line_frame_with_json() {
        assert_eq!(
            sse_line_frame("{\"status\":\"ok\"}"),
            "event: line\ndata: {\"status\":\"ok\"}\n\n"
        );
    }

    #[test]
    fn test_sse_line_frame_with_newlines() {
        assert_eq!(
            sse_line_frame("line1\nline2"),
            "event: line\ndata: line1\nline2\n\n"
        );
    }

    #[test]
    fn test_sse_line_frame_preserves_content() {
        let payload = "test payload with spaces";
        let frame = sse_line_frame(payload);
        assert!(frame.starts_with("event: line\ndata: "));
        assert!(frame.ends_with("\n\n"));
        assert!(frame.contains(payload));
    }
}
