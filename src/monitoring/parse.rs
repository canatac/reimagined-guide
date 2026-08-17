/// Parse SMTP error code from an error string (e.g. "Unexpected response: 550 …").
pub fn parse_smtp_code(msg: &str) -> Option<u16> {
    msg.split_whitespace()
        .find_map(|w| w.parse::<u16>().ok().filter(|&c| (200..600).contains(&c)))
}
