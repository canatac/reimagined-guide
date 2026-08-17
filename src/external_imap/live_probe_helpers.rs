/*!
 * Helpers extracted from live_probe.rs (Cycle 48).
 */

pub fn escape_imap(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn sse_line_frame(payload: &str) -> String {
    format!("event: line\ndata: {payload}\n\n")
}
