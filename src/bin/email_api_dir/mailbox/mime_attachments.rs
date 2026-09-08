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
