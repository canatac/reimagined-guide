// Email Import Wizard (Issue #491) — autodiscover + validate endpoints.

#![allow(unused_imports)]
use super::super::*;

/// POST /api/external-accounts/wizard/autodiscover
/// Body: { email }
pub(crate) async fn api_wizard_autodiscover(
    payload: web::Json<WizardAutodiscoverInput>,
) -> impl Responder {
    let email = payload.into_inner().email;
    let result = simple_smtp_server::external_imap::import_wizard::autodiscover(&email);
    HttpResponse::Ok().json(result)
}

/// POST /api/external-accounts/wizard/validate
/// Body: { provider, email, auth_type, imap: {host, port, tls}, password }
pub(crate) async fn api_wizard_validate(
    payload: web::Json<simple_smtp_server::external_imap::import_wizard::WizardCredentialsInput>,
) -> impl Responder {
    let input = payload.into_inner();

    // Honor provider preset if auth_type=password and imap host is empty.
    // This lets the UI send just a provider name + password.
    let input = if input.imap.host.is_empty() {
        if let Some(preset) =
            simple_smtp_server::external_imap::import_wizard::preset_for(&input.provider)
        {
            simple_smtp_server::external_imap::import_wizard::WizardCredentialsInput {
                imap: preset.imap,
                email: input.email,
                auth_type: input.auth_type,
                provider: input.provider,
                password: input.password,
            }
        } else {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "ok": false,
                "error": {"code": "UNKNOWN_PROVIDER", "message": format!("Unknown provider: {}", input.provider)}
            }));
        }
    } else {
        input
    };

    let result =
        simple_smtp_server::external_imap::import_wizard::validate_credentials(&input);
    if result.ok {
        HttpResponse::Ok().json(result)
    } else {
        HttpResponse::BadRequest().json(result)
    }
}

/// POST /api/external-accounts/wizard/preset
/// Body: { provider }
pub(crate) async fn api_wizard_preset(
    payload: web::Json<WizardPresetInput>,
) -> impl Responder {
    let provider = payload.into_inner().provider;
    match simple_smtp_server::external_imap::import_wizard::preset_for(&provider) {
        Some(preset) => HttpResponse::Ok().json(preset),
        None => HttpResponse::NotFound().json(serde_json::json!({
            "ok": false,
            "error": {"code": "UNKNOWN_PROVIDER", "message": format!("Unknown provider: {}", provider)}
        })),
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WizardAutodiscoverInput {
    pub email: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WizardPresetInput {
    pub provider: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autodiscover_gmail_via_endpoint() {
        let result = simple_smtp_server::external_imap::import_wizard::autodiscover("alice@gmail.com");
        assert!(result.detected);
        assert_eq!(result.provider, "gmail");
    }

    #[test]
    fn preset_for_known_provider() {
        let p = simple_smtp_server::external_imap::import_wizard::preset_for("gmail");
        assert!(p.is_some());
        let p = p.unwrap();
        assert_eq!(p.imap.host, "imap.gmail.com");
    }

    #[test]
    fn validate_credentials_empty_password() {
        let input = simple_smtp_server::external_imap::import_wizard::WizardCredentialsInput {
            provider: "gmail".into(),
            email: "test@gmail.com".into(),
            auth_type: "password".into(),
            imap: simple_smtp_server::external_imap::ExternalImapServerConfig {
                host: "imap.gmail.com".into(),
                port: 993,
                tls: true,
            },
            password: "".into(),
        };
        let result = simple_smtp_server::external_imap::import_wizard::validate_credentials(&input);
        assert!(!result.ok);
        assert!(result.message.contains("Password"));
    }
}
