//! Parsing headers d'emails entrants + extraction contenu.
//! Extrait de smtp_server.rs (refactor cycle 6).
#![allow(dead_code)]

use mailparse::parse_mail;
use simple_smtp_server::smtp_client::extract_email_address;
use std::sync::atomic::{AtomicU64, Ordering};

use super::CustomEmail;

const MAX_HEADER_LINE_LEN: usize = 8 * 1024;
const MAX_HEADER_NAME_LEN: usize = 128;
const MAX_HEADER_VALUE_LEN: usize = 16 * 1024;

static HEADER_REJECT_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderParseReject {
    MissingSeparator,
    EmptyName,
    InvalidName,
    AmbiguousValue,
    HeaderLineTooLong,
    HeaderValueTooLong,
    FoldedWithoutPrevious,
}

impl HeaderParseReject {
    pub(crate) fn reason_code(self) -> &'static str {
        match self {
            Self::MissingSeparator => "missing_separator",
            Self::EmptyName => "empty_name",
            Self::InvalidName => "invalid_name",
            Self::AmbiguousValue => "ambiguous_value",
            Self::HeaderLineTooLong => "header_line_too_long",
            Self::HeaderValueTooLong => "header_value_too_long",
            Self::FoldedWithoutPrevious => "folded_without_previous",
        }
    }
}

fn reject(reason: HeaderParseReject) -> Result<(String, String), HeaderParseReject> {
    HEADER_REJECT_COUNT.fetch_add(1, Ordering::Relaxed);
    Err(reason)
}

pub(crate) fn security_header_reject_count() -> u64 {
    HEADER_REJECT_COUNT.load(Ordering::Relaxed)
}

fn is_valid_header_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_HEADER_NAME_LEN {
        return false;
    }
    name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

pub(crate) fn extract_session_id_from_response(response: &str) -> Option<String> {
    let marker = "session ID:";
    let idx = response.find(marker)?;
    let sid = response[idx + marker.len()..]
        .trim()
        .trim_end_matches('\r')
        .trim_end_matches('\n')
        .to_string();
    if sid.is_empty() {
        None
    } else {
        Some(sid)
    }
}

pub(crate) fn parse_header_line(raw_line: &str) -> Result<(String, String), HeaderParseReject> {
    if raw_line.len() > MAX_HEADER_LINE_LEN {
        return reject(HeaderParseReject::HeaderLineTooLong);
    }

    if raw_line.as_bytes().iter().any(|b| *b == b'\0' || *b == b'\r' || *b == b'\n') {
        return reject(HeaderParseReject::AmbiguousValue);
    }

    let (name, value) = raw_line
        .split_once(':')
        .ok_or(HeaderParseReject::MissingSeparator)
        .or_else(reject)?;
    let name = name.trim();
    if name.is_empty() {
        return reject(HeaderParseReject::EmptyName);
    }

    if !is_valid_header_name(name) {
        return reject(HeaderParseReject::InvalidName);
    }

    let value = value.trim();
    if value.len() > MAX_HEADER_VALUE_LEN {
        return reject(HeaderParseReject::HeaderValueTooLong);
    }

    Ok((name.to_string(), value.to_string()))
}

pub(crate) fn parse_message_id_header(value: &str) -> Option<String> {
    let value = value
        .trim_matches(|c| c == '<' || c == '>')
        .trim();

    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

pub(crate) fn apply_parsed_header(
    current_email: &mut CustomEmail,
    raw_line: &str,
) -> Result<(), HeaderParseReject> {
    if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
        if let Some((last_name, last_value)) = current_email.email.headers.last_mut() {
            let continuation = raw_line.trim();
            if !continuation.is_empty() {
                if !last_value.is_empty() {
                    last_value.push(' ');
                }
                last_value.push_str(continuation);

                if last_name.eq_ignore_ascii_case("DKIM-Signature") {
                    current_email.dkim_signature = Some(last_value.clone());
                } else if last_name.eq_ignore_ascii_case("Subject") {
                    current_email.email.subject = last_value.clone();
                } else if last_name.eq_ignore_ascii_case("Message-ID") {
                    if let Some(mid) = parse_message_id_header(last_value) {
                        current_email.email.id = mid;
                    }
                }
            }
        } else {
            HEADER_REJECT_COUNT.fetch_add(1, Ordering::Relaxed);
            return Err(HeaderParseReject::FoldedWithoutPrevious);
        }
        return Ok(());
    }

    let (name, value) = parse_header_line(raw_line)?;
    current_email
        .email
        .headers
        .push((name.clone(), value.clone()));

    if name.eq_ignore_ascii_case("DKIM-Signature") {
        current_email.dkim_signature = Some(value.clone());
    } else if name.eq_ignore_ascii_case("From") {
        let canonical = format!("From: {}", value);
        current_email.email.from =
            extract_email_address(&canonical, "From:").unwrap_or_default();
    } else if name.eq_ignore_ascii_case("To") {
        let canonical = format!("To: {}", value);
        current_email.email.to = extract_email_address(&canonical, "To:").unwrap_or_default();
    } else if name.eq_ignore_ascii_case("Subject") {
        current_email.email.subject = value;
    } else if name.eq_ignore_ascii_case("Message-ID") {
        if let Some(mid) = parse_message_id_header(&value) {
            current_email.email.id = mid;
        }
    }

    Ok(())
}

pub(crate) fn extract_email_content(
    email_content: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let parsed = parse_mail(email_content.as_bytes())?;

    if let Some(plain_text) = parsed
        .subparts
        .iter()
        .find(|part| part.ctype.mimetype == "text/plain")
    {
        return Ok(plain_text.get_body()?.trim().to_string());
    }

    if let Some(html) = parsed
        .subparts
        .iter()
        .find(|part| part.ctype.mimetype == "text/html")
    {
        let html_content = html.get_body()?;
        return Ok(html_content
            .replace(['<', '>'], "")
            .trim()
            .to_string());
    }

    Ok(parsed.get_body()?.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_email_content_plain_text() {
        let email_content = "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nThis is a plain text email.";
        let result = extract_email_content(email_content).unwrap();
        assert_eq!(result, "This is a plain text email.");
    }

    #[test]
    fn test_extract_email_content_html() {
        let email_content = "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nContent-Type: text/html\r\n\r\n<html><body>This is an <b>HTML</b> email.</body></html>";
        let result = extract_email_content(email_content).unwrap();
        assert_eq!(
            result,
            "<html><body>This is an <b>HTML</b> email.</body></html>"
        );
    }

    #[test]
    fn test_extract_email_content_no_body() {
        let email_content =
            "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n";
        let result = extract_email_content(email_content).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_parse_header_line_rejects_ambiguous() {
        let start = security_header_reject_count();
        let err = parse_header_line("Subject\0: x").unwrap_err();
        assert_eq!(err, HeaderParseReject::AmbiguousValue);
        assert!(security_header_reject_count() >= start + 1);
    }

    #[test]
    fn test_parse_header_line_rejects_invalid_name() {
        let err = parse_header_line("Bad Name: x").unwrap_err();
        assert_eq!(err, HeaderParseReject::InvalidName);
    }

    #[test]
    fn test_parse_header_line_accepts_standard_name() {
        let (name, value) = parse_header_line("Message-ID: <abc>").unwrap();
        assert_eq!(name, "Message-ID");
        assert_eq!(value, "<abc>");
    }
}
