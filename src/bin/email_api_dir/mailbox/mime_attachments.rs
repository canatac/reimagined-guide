// MIME attachment extraction extracted from mime_utils.rs (Sprint 17)
use super::super::*;
use super::mime_body::{looks_like_raw_multipart_dump, raw_mime_from_email};

fn infer_attachment_kind(content_type: &str, filename: &str) -> &'static str {
    let ct = content_type.to_ascii_lowercase();
    let lower_name = filename.to_ascii_lowercase();
    if ct.starts_with("image/") {
        "image"
    } else if ct == "application/pdf" || lower_name.ends_with(".pdf") {
        "pdf"
    } else if ct.contains("word")
        || lower_name.ends_with(".doc")
        || lower_name.ends_with(".docx")
        || lower_name.ends_with(".odt")
    {
        "doc"
    } else if ct.contains("sheet")
        || lower_name.ends_with(".xls")
        || lower_name.ends_with(".xlsx")
        || lower_name.ends_with(".csv")
    {
        "spreadsheet"
    } else if ct.contains("presentation")
        || lower_name.ends_with(".ppt")
        || lower_name.ends_with(".pptx")
    {
        "presentation"
    } else if ct.starts_with("audio/") {
        "audio"
    } else if ct.starts_with("video/") {
        "video"
    } else if ct.contains("zip")
        || ct.contains("gzip")
        || ct.contains("tar")
        || ct.contains("7z")
        || lower_name.ends_with(".zip")
        || lower_name.ends_with(".tar")
        || lower_name.ends_with(".gz")
        || lower_name.ends_with(".7z")
    {
        "archive"
    } else {
        "other"
    }
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
    let disp_kind = format!("{:?}", disp.disposition).to_ascii_lowercase();
    let filename = disp
        .params
        .get("filename")
        .cloned()
        .or_else(|| part.ctype.params.get("name").cloned())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("attachment-{}", *index + 1));

    let is_attachment = disp_kind == "attachment"
        || disp.params.contains_key("filename")
        || part.ctype.params.contains_key("name")
        || (!content_type.starts_with("text/") && content_type != "application/pgp-signature");

    if !is_attachment {
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
