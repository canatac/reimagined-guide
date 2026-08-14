// oauth_utils.rs — split from main.rs (Sprint 9)
#![allow(unused_imports)]
use super::*;
use crate::{monitoring, security, admin_ops, monitoring_handlers};

pub(crate) fn normalize_segment(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'à' | 'â' | 'ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'î' | 'ï' => 'i',
            'ô' | 'ö' => 'o',
            'ù' | 'û' | 'ü' => 'u',
            'ç' => 'c',
            'ñ' => 'n',
            'æ' => 'a',
            'œ' => 'o',
            _ => c,
        })
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Retourne `prenom.nom` normalisé, ou None si prénom ou nom est absent.
pub(crate) fn build_misfits_local(first_name: &str, last_name: &str) -> Option<String> {
    let first = normalize_segment(first_name.trim());
    let last = normalize_segment(last_name.trim());
    if first.is_empty() || last.is_empty() {
        return None;
    }
    Some(format!("{}.{}", first, last))
}

pub(crate) fn normalize_oauth_provider(provider: &str) -> Option<String> {
    let p = provider.trim().to_ascii_lowercase();
    match p.as_str() {
        "github" => Some(p),
        _ => None,
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct EmailRequest {
    from: String,
    to: String,
    subject: String,
    body: String,
}

#[derive(Deserialize)]
struct MailingListRequest {
    label: String,
    emails: Vec<String>,
}

#[derive(Deserialize)]
struct MailingListEmailRequest {
    from: String,
    subject: String,
    body: String,
    mailing_list: String,
}

