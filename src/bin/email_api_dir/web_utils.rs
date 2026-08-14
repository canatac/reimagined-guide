// web_utils.rs — split from main.rs (Sprint 9)
#![allow(unused_imports)]
use super::*;

fn req_ip_str(req: &actix_web::HttpRequest) -> String {
    req.connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .split(':')
        .next()
        .unwrap_or("unknown")
        .to_string()
}

fn get_accept_language(req: &actix_web::HttpRequest) -> String {
    req.headers()
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn welcome_email_html(
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

// auth_login..api_password_reset_confirm → auth_handlers module

// mailbox + send + drafts → mailbox_handlers module
// admin CRUD + change-requests + deliverability → admin_ops_handlers module

#[actix_web::main]
