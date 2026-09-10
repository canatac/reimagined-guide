//! # Email Import Wizard Backend (Issue #491)
//!
//! Provides a 3-step wizard to connect an external email account:
//! 1. Provider preset / autodiscover — given an email, return the known
//!    IMAP/SMTP configuration (Gmail, Outlook, Yahoo, or manual).
//! 2. Validate credentials — live IMAP probe (capabilities + login).
//! 3. Create the external account in MongoDB.
//!
//! Zero-local-build constraints apply: all IMAP I/O happens on worker threads
//! via the existing `dialog_helpers::imap_probe` path.

use serde::{Deserialize, Serialize};

use super::dialog_helpers::imap_probe;
use super::ExternalImapServerConfig;

// ─────────────────────────────────────────────────────────────────────────
// Provider presets
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderPreset {
    Gmail,
    Outlook,
    Yahoo,
    Imap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmtpPreset {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportWizardPreset {
    pub provider: String,
    pub imap: ExternalImapServerConfig,
    pub smtp: Option<SmtpPreset>,
    /// Whether OAuth2 is supported by this provider.
    pub oauth2_supported: bool,
    /// Human-readable hint shown in the UI (e.g. "App password required").
    pub hint: String,
}

/// Return the known preset for a provider slug, or None if not recognised.
pub fn preset_for(provider: &str) -> Option<ImportWizardPreset> {
    match provider.to_ascii_lowercase().as_str() {
        "gmail" | "google" => Some(ImportWizardPreset {
            provider: "gmail".into(),
            imap: ExternalImapServerConfig {
                host: "imap.gmail.com".into(),
                port: 993,
                tls: true,
            },
            smtp: Some(SmtpPreset {
                host: "smtp.gmail.com".into(),
                port: 587,
                tls: true,
            }),
            oauth2_supported: true,
            hint: "Use an App Password or OAuth2. Less secure apps are blocked.".into(),
        }),
        "outlook" | "office365" | "microsoft" | "hotmail" | "live" => Some(ImportWizardPreset {
            provider: "outlook".into(),
            imap: ExternalImapServerConfig {
                host: "outlook.office365.com".into(),
                port: 993,
                tls: true,
            },
            smtp: Some(SmtpPreset {
                host: "smtp.office365.com".into(),
                port: 587,
                tls: true,
            }),
            oauth2_supported: true,
            hint: "Modern Auth (OAuth2) is required for new accounts.".into(),
        }),
        "yahoo" => Some(ImportWizardPreset {
            provider: "yahoo".into(),
            imap: ExternalImapServerConfig {
                host: "imap.mail.yahoo.com".into(),
                port: 993,
                tls: true,
            },
            smtp: Some(SmtpPreset {
                host: "smtp.mail.yahoo.com".into(),
                port: 587,
                tls: true,
            }),
            oauth2_supported: true,
            hint: "Generate an App Password from Yahoo Account Security.".into(),
        }),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Autodiscover
// ─────────────────────────────────────────────────────────────────────────

/// Best-effort provider detection from an email domain.
///
/// Strategy (no external DNS dependency — pure string matching on the most
/// common providers). For unknown domains we return a synthetic "manual"
/// response so the UI can show a generic IMAP form.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutodiscoverResult {
    pub detected: bool,
    pub provider: String,
    pub preset: Option<ImportWizardPreset>,
    pub domain: String,
}

pub fn autodiscover(email: &str) -> AutodiscoverResult {
    let domain = email
        .split('@')
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if domain.is_empty() {
        return AutodiscoverResult {
            detected: false,
            provider: "unknown".into(),
            preset: None,
            domain,
        };
    }

    // Direct provider match on well-known domains.
    let provider_slug = match domain.as_str() {
        "gmail.com" | "googlemail.com" => "gmail",
        "outlook.com" | "hotmail.com" | "live.com" | "msn.com" | "outlook.fr" | "hotmail.fr" | "live.fr" => "outlook",
        "yahoo.com" | "yahoo.fr" | "ymail.com" | "rocketmail.com" => "yahoo",
        _ => "",
    };

    if provider_slug.is_empty() {
        return AutodiscoverResult {
            detected: false,
            provider: "manual".into(),
            preset: None,
            domain,
        };
    };

    let preset = preset_for(provider_slug);
    let provider = preset.as_ref().map(|p| p.provider.clone()).unwrap_or_default();
    AutodiscoverResult {
        detected: true,
        provider,
        preset,
        domain,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Validation DTOs (step 2)
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WizardCredentialsInput {
    pub provider: String,
    pub email: String,
    pub auth_type: String,
    pub imap: ExternalImapServerConfig,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WizardValidationResult {
    pub ok: bool,
    pub message: String,
    pub capabilities: Vec<String>,
    pub greeting: String,
    /// Folder list as returned by IMAP LIST (may be empty if not requested).
    pub folders: Vec<String>,
}

/// Live IMAP validation. Spans the same code path as the existing probe,
/// returning capabilities + greeting + folder list on success.
pub fn validate_credentials(input: &WizardCredentialsInput) -> WizardValidationResult {
    if input.password.is_empty() {
        return WizardValidationResult {
            ok: false,
            message: "Password is required".into(),
            capabilities: Vec::new(),
            greeting: String::new(),
            folders: Vec::new(),
        };
    }

    match imap_probe(
        &input.imap.host,
        input.imap.port,
        input.imap.tls,
        &input.email,
        &input.password,
        true,
    ) {
        Ok((greeting, capabilities, folders)) => WizardValidationResult {
            ok: true,
            message: if folders.is_empty() {
                "Connected. Login successful (no folders listed).".into()
            } else {
                format!("Connected. Login successful, {} folder(s).", folders.len())
            },
            capabilities,
            greeting,
            folders,
        },
        Err(e) => WizardValidationResult {
            ok: false,
            message: e,
            capabilities: Vec::new(),
            greeting: String::new(),
            folders: Vec::new(),
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_gmail() {
        let p = preset_for("gmail").expect("gmail preset");
        assert_eq!(p.imap.host, "imap.gmail.com");
        assert_eq!(p.imap.port, 993);
        assert!(p.imap.tls);
        assert!(p.oauth2_supported);
        assert!(p.smtp.is_some());
    }

    #[test]
    fn preset_outlook() {
        let p = preset_for("outlook").expect("outlook preset");
        assert_eq!(p.imap.host, "outlook.office365.com");
        assert_eq!(p.smtp.as_ref().unwrap().port, 587);
    }

    #[test]
    fn preset_yahoo() {
        let p = preset_for("yahoo").expect("yahoo preset");
        assert_eq!(p.imap.host, "imap.mail.yahoo.com");
        assert!(p.hint.contains("App Password"));
    }

    #[test]
    fn preset_unknown_returns_none() {
        assert!(preset_for("totally_random_provider_42").is_none());
    }

    #[test]
    fn autodetect_gmail() {
        let r = autodiscover("alice@gmail.com");
        assert!(r.detected);
        assert_eq!(r.provider, "gmail");
        assert!(r.preset.is_some());
    }

    #[test]
    fn autodetect_outlook_alias() {
        let r = autodiscover("bob@hotmail.fr");
        assert!(r.detected);
        assert_eq!(r.provider, "outlook");
    }

    #[test]
    fn autodetect_manual() {
        let r = autodiscover("user@custom-company.eu");
        assert!(!r.detected);
        assert_eq!(r.provider, "manual");
        assert!(r.preset.is_none());
    }

    #[test]
    fn autodetect_empty_domain() {
        let r = autodiscover("noatsign");
        assert!(!r.detected);
        assert_eq!(r.provider, "unknown");
    }

    #[test]
    fn validate_rejects_empty_password() {
        let input = WizardCredentialsInput {
            provider: "gmail".into(),
            email: "a@gmail.com".into(),
            auth_type: "password".into(),
            imap: ExternalImapServerConfig {
                host: "imap.gmail.com".into(),
                port: 993,
                tls: true,
            },
            password: "".into(),
        };
        let r = validate_credentials(&input);
        assert!(!r.ok);
        assert!(r.message.contains("Password"));
    }

    #[test]
    fn autodiscover_uppercase_email() {
        let r = autodiscover("Alice@GMAIL.COM");
        assert!(r.detected);
        assert_eq!(r.provider, "gmail");
    }

    #[test]
    fn autodiscover_with_subdomain() {
        let r = autodiscover("user@mail.gmail.com");
        // "mail.gmail.com" is not in the exact-match list → manual
        assert!(!r.detected);
        assert_eq!(r.provider, "manual");
    }

    #[test]
    fn preset_case_insensitive() {
        let p = preset_for("GMAIL");
        assert!(p.is_some());
        assert_eq!(p.unwrap().provider, "gmail");
    }

    #[test]
    fn preset_outlook_alias_office365() {
        let p = preset_for("office365").expect("office365 preset");
        assert_eq!(p.imap.host, "outlook.office365.com");
        assert_eq!(p.smtp.as_ref().unwrap().host, "smtp.office365.com");
    }

    #[test]
    fn preset_yahoo_alias_ymail() {
        let p = preset_for("ymail.com");
        assert!(p.is_some());
        assert_eq!(p.unwrap().provider, "yahoo");
    }

    #[test]
    fn autodiscover_yahoo_domain() {
        let r = autodiscover("user@yahoo.fr");
        assert!(r.detected);
        assert_eq!(r.provider, "yahoo");
    }

    #[test]
    fn autodiscover_msn_domain() {
        let r = autodiscover("user@msn.com");
        assert!(r.detected);
        assert_eq!(r.provider, "outlook");
    }
}
