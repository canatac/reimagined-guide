//! Helpers purs de l'API email (refactor architecte).
//! Extraits de main.rs (1556 LOC) pour améliorer maintenabilité et testabilité.

use actix_web::HttpRequest;
use simple_smtp_server::i18n;

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

pub(crate) fn req_ip_str(req: &actix_web::HttpRequest) -> String {
    req.connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .split(':')
        .next()
        .unwrap_or("unknown")
        .to_string()
}

pub(crate) fn get_accept_language(req: &actix_web::HttpRequest) -> String {
    req.headers()
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

pub(crate) fn welcome_email_html(
    locale: &str,
    display_name: &str,
    primary_email: &str,
    alias_email: Option<&str>,
) -> String {
    let dir = if i18n::is_rtl(locale) { "rtl" } else { "ltr" };
    let text_align = if i18n::is_rtl(locale) {
        "right"
    } else {
        "left"
    };
    let greeting = i18n::t(locale, "email-welcome-greeting", &[("name", display_name)]);
    let intro = i18n::t(locale, "email-welcome-intro", &[]);
    let primary_label = i18n::t(locale, "email-welcome-primary-label", &[]);
    let cta = i18n::t(locale, "email-welcome-cta", &[]);
    let signature = i18n::t(locale, "email-welcome-signature", &[]);
    let alias_row = alias_email
        .map(|a| {
            let lbl = i18n::t(locale, "email-welcome-alias-label", &[]);
            let detail = i18n::t(locale, "email-welcome-alias-detail", &[]);
            format!(
                "<tr><td style=\"padding:4px 0\"><b>{lbl}</b> \
                 <span class=\"addr\">{a}</span> {detail}</td></tr>"
            )
        })
        .unwrap_or_default();
    format!(
        r#"<!DOCTYPE html>
<html lang="{locale}" dir="{dir}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <style>
    body{{font-family:Tahoma,Arial,sans-serif;direction:{dir};text-align:{text_align};color:#222;background:#f5f5f5;margin:0;padding:0}}
    .wrap{{max-width:600px;margin:40px auto;background:#fff;border-radius:8px;padding:40px}}
    .addr{{font-family:monospace;background:#f0f0f0;padding:2px 6px;border-radius:3px}}
  </style>
</head>
<body><div class="wrap">
  <h2>{greeting}</h2>
  <p>{intro}</p>
  <table cellpadding="0" cellspacing="0">
    <tr><td style="padding:4px 0"><b>{primary_label}</b> <span class="addr">{primary_email}</span></td></tr>
    {alias_row}
  </table>
  <p>{cta}</p>
  <p>{signature}</p>
</div></body>
</html>"#,
    )
}

