// MIME attachment extraction extracted from mime_utils.rs (Sprint 17)
use super::super::*;
use super::mime_body::{looks_like_raw_multipart_dump, raw_mime_from_email};

fn infer_attachment_kind(content_type: &str, filename: &str) -> &'static str {
    let ct = content_type.to_ascii_lowercase();
    let lower_name = filename.to_ascii_lowercase();
    if ct.starts_with("image/") {
        return "image";
    }

    if let Some(kind) = media_kind(&ct) {
        return kind;
    }

    const KIND_RULES: &[(&str, &[&str], &[&str])] = &[
        ("pdf", &["application/pdf"], &[".pdf"]),
        ("doc", &["word"], &[".doc", ".docx", ".odt"]),
        ("spreadsheet", &["sheet"], &[".xls", ".xlsx", ".csv"]),
        ("presentation", &["presentation"], &[".ppt", ".pptx"]),
        ("archive", &["zip", "gzip", "tar", "7z"], &[".zip", ".tar", ".gz", ".7z"]),
    ];

    for (kind, content_type_hints, extension_hints) in KIND_RULES {
        if kind_matches(&ct, &lower_name, content_type_hints, extension_hints) {
            return kind;
        }
    }

    "other"
}

fn media_kind(content_type: &str) -> Option<&'static str> {
    if content_type.starts_with("audio/") {
        Some("audio")
    } else if content_type.starts_with("video/") {
        Some("video")
    } else {
        None
    }
}

fn kind_matches(content_type: &str, filename: &str, content_type_hints: &[&str], extension_hints: &[&str]) -> bool {
    content_type_hints.iter().any(|hint| content_type.contains(hint))
        || extension_hints
            .iter()
            .any(|extension| filename.ends_with(extension))
}

#[derive(Clone)]
pub(crate) struct ExtractedAttachment {
    pub id: String,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub kind: String,
    pub data: Vec<u8>,
}

fn walk_mime_attachments(
    part: &mailparse::ParsedMail<'_>,
    out: &mut Vec<ExtractedAttachment>,
    index: &mut usize,
) {
    if !part.subparts.is_empty() {
        for sub in &part.subparts {
            walk_mime_attachments(sub, out, index);
        }
        return;
    }

    let content_type = part.ctype.mimetype.to_ascii_lowercase();
    let disp = part.get_content_disposition();
    let filename = attachment_filename(part, &disp, *index + 1);
    if !is_attachment_part(&content_type, part, &disp) {
        return;
    }

    let bytes = part.get_body_raw().unwrap_or_default();
    let kind = infer_attachment_kind(&content_type, &filename).to_string();
    let id = format!("att-{}", *index);
    *index += 1;

    out.push(ExtractedAttachment {
        id,
        filename,
        content_type,
        size: bytes.len() as u64,
        kind,
        data: bytes,
    });
}

fn attachment_filename(
    part: &mailparse::ParsedMail<'_>,
    disp: &mailparse::ParsedContentDisposition,
    fallback_index: usize,
) -> String {
    disp.params
        .get("filename")
        .cloned()
        .or_else(|| part.ctype.params.get("name").cloned())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("attachment-{}", fallback_index))
}

fn is_attachment_part(
    content_type: &str,
    part: &mailparse::ParsedMail<'_>,
    disp: &mailparse::ParsedContentDisposition,
) -> bool {
    let disp_kind = format!("{:?}", disp.disposition).to_ascii_lowercase();
    let declared_attachment = disp_kind == "attachment"
        || disp.params.contains_key("filename")
        || part.ctype.params.contains_key("name");
    let implicit_binary = !content_type.starts_with("text/") && content_type != "application/pgp-signature";
    declared_attachment || implicit_binary
}

pub(crate) fn extract_attachments_for_ui(email: &Email) -> Vec<ExtractedAttachment> {
    let raw_mime = raw_mime_from_email(email);
    if let Ok(parsed) = mailparse::parse_mail(raw_mime.as_bytes()) {
        let mut out = Vec::new();
        let mut idx = 0usize;
        walk_mime_attachments(&parsed, &mut out, &mut idx);
        return out;
    }

    if looks_like_raw_multipart_dump(&email.body) {
        let first_line = match email.body.lines().next() {
            Some(l) => l.trim(),
            None => return Vec::new(),
        };
        let boundary = first_line
            .trim_start_matches("--")
            .trim_end_matches("--")
            .trim();
        if boundary.is_empty() {
            return Vec::new();
        }
        let synthetic = format!(
            "Content-Type: multipart/mixed; boundary=\"{}\"\r\n\r\n{}",
            boundary, email.body
        );
        if let Ok(parsed) = mailparse::parse_mail(synthetic.as_bytes()) {
            let mut out = Vec::new();
            let mut idx = 0usize;
            walk_mime_attachments(&parsed, &mut out, &mut idx);
            return out;
        }
    }

    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infer_attachment_kind_image() {
        assert_eq!(infer_attachment_kind("image/png", "photo.png"), "image");
    }

    #[test]
    fn infer_attachment_kind_pdf() {
        assert_eq!(
            infer_attachment_kind("application/pdf", "doc.pdf"),
            "pdf"
        );
    }

    #[test]
    fn infer_attachment_kind_doc() {
        assert_eq!(
            infer_attachment_kind("application/msword", "doc.doc"),
            "doc"
        );
    }

    #[test]
    fn infer_attachment_kind_spreadsheet() {
        assert_eq!(
            infer_attachment_kind("application/vnd.ms-excel", "data.xls"),
            "spreadsheet"
        );
    }

    #[test]
    fn infer_attachment_kind_presentation() {
        assert_eq!(
            infer_attachment_kind("application/vnd.ms-powerpoint", "slides.ppt"),
            "presentation"
        );
    }

    #[test]
    fn infer_attachment_kind_archive() {
        assert_eq!(infer_attachment_kind("application/zip", "file.zip"), "archive");
    }

    #[test]
    fn infer_attachment_kind_audio() {
        assert_eq!(
            infer_attachment_kind("audio/mpeg", "song.mp3"),
            "audio"
        );
    }

    #[test]
    fn infer_attachment_kind_video() {
        assert_eq!(
            infer_attachment_kind("video/mp4", "video.mp4"),
            "video"
        );
    }

    #[test]
    fn infer_attachment_kind_other() {
        assert_eq!(
            infer_attachment_kind("application/octet-stream", "file.bin"),
            "other"
        );
    }

    #[test]
    fn extract_attachments_for_ui_no_attachments() {
        let email = Email {
            id: String::new(),
            from: String::new(),
            to: String::new(),
            subject: String::new(),
            body: "plain text".to_string(),
            headers: vec![],
            flags: vec![],
            sequence_number: 0,
            uid: 0,
            internal_date: chrono::Utc::now(),
            dkim_signature: None,
        };
        let attachments = extract_attachments_for_ui(&email);
        assert!(attachments.is_empty());
    }

    #[test]
    fn extract_attachments_for_ui_with_pdf() {
        let raw = "Content-Type: multipart/mixed; boundary=\"abc\"\r\n\r\n--abc\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"test.pdf\"\r\n\r\nfakepdfcontent\r\n--abc--\r\n";
        let email = Email {
            id: String::new(),
            from: String::new(),
            to: String::new(),
            subject: String::new(),
            body: raw.to_string(),
            headers: vec![("Content-Type".to_string(), "multipart/mixed; boundary=\"abc\"".to_string())],
            flags: vec![],
            sequence_number: 0,
            uid: 0,
            internal_date: chrono::Utc::now(),
            dkim_signature: None,
        };
        let attachments = extract_attachments_for_ui(&email);
        assert!(!attachments.is_empty());
        assert_eq!(attachments[0].kind, "pdf");
    }

    #[test]
    fn extract_attachments_for_ui_with_image() {
        let raw = "Content-Type: multipart/mixed; boundary=\"xyz\"\r\n\r\n--xyz\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=\"photo.png\"\r\n\r\nfakeimage\r\n--xyz--\r\n";
        let email = Email {
            id: String::new(),
            from: String::new(),
            to: String::new(),
            subject: String::new(),
            body: raw.to_string(),
            headers: vec![("Content-Type".to_string(), "multipart/mixed; boundary=\"xyz\"".to_string())],
            flags: vec![],
            sequence_number: 0,
            uid: 0,
            internal_date: chrono::Utc::now(),
            dkim_signature: None,
        };
        let attachments = extract_attachments_for_ui(&email);
        assert!(!attachments.is_empty());
        assert_eq!(attachments[0].kind, "image");
    }
}
