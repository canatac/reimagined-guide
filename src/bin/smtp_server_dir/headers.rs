// Split from smtp_server.rs — parsing d'en-têtes MIME.
use super::CustomEmail;

pub(crate) fn parse_header_line(raw_line: &str) -> Option<(String, String)> {
    let (name, value) = raw_line.split_once(':')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), value.trim().to_string()))
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

pub(crate) fn apply_parsed_header(current_email: &mut CustomEmail, raw_line: &str) {
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
        }
        return;
    }

    if let Some((name, value)) = parse_header_line(raw_line) {
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
    }
}

pub(crate) fn extract_session_id_from_response(response: &str) -> Option<String> {
    let marker = "session ID:";
    let idx = response.find(marker)?;
    let sid = response[idx + marker.len()..]
        .trim()
        .trim_end_matches('\r')
        .trim_end_matches('\n')
        .to_string();
    if sid.is_empty() { None } else { Some(sid) }
}
