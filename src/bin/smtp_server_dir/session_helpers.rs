//! Helpers partagés entre `handle_plain_client` et `handle_tls_client`.
//! Extraction pure : aucun changement de comportement.
#![allow(unused_imports, dead_code)]

use std::sync::Arc;

use log::error;
use tokio::net::TcpStream;

use simple_smtp_server::entities::Email;
use simple_smtp_server::logic::Logic;
use simple_smtp_server::session::SessionManager;
use simple_smtp_server::smtp_client::send_outgoing_email;

use std::env;

use super::{
    CustomEmail, StreamType, MailServer,
    apply_parsed_header, write_response,
    headers_helpers::HeaderParseReject,
    recipient_helpers::{is_local_recipient, recipient_local_part},
};

/// Construit un `Email` complet à partir du `CustomEmail` en cours d'accumulation.
pub(crate) fn email_from_current(current: &CustomEmail) -> Email {
    Email {
        id: current.email.id.clone(),
        from: current.email.from.clone(),
        to: current.email.to.clone(),
        subject: current.email.subject.clone(),
        body: current.email.body.clone(),
        headers: current.email.headers.clone(),
        flags: current.email.flags.clone(),
        sequence_number: current.email.sequence_number,
        uid: current.email.uid,
        internal_date: current.email.internal_date,
        dkim_signature: current.dkim_signature.clone(),
    }
}

/// Résout `(user, mailbox)` pour un mail entrant, soit via la session
/// authentifiée, soit via le local-part du destinataire.
pub(crate) fn resolve_route(
    authenticated_session_id: Option<&String>,
    session_manager: &Arc<SessionManager>,
    to: &str,
) -> Option<(String, String)> {
    if let Some(session_id) = authenticated_session_id {
        let username = session_manager.get_username(session_id);
        let mailbox = session_manager.get_mailbox(session_id);
        username.zip(mailbox)
    } else {
        recipient_local_part(to).map(|user| (user, "inbox".to_string()))
    }
}

/// True si `USE_MONGODB=true`.
pub(crate) fn use_mongodb_env() -> bool {
    env::var("USE_MONGODB").unwrap_or_else(|_| "false".to_string()) == "true"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn use_mongodb_env_default_false() {
        std::env::remove_var("USE_MONGODB");
        assert!(!use_mongodb_env());
    }

    #[test]
    fn use_mongodb_env_true() {
        std::env::set_var("USE_MONGODB", "true");
        assert!(use_mongodb_env());
        std::env::remove_var("USE_MONGODB");
    }

    #[test]
    fn use_mongodb_env_false_explicit() {
        std::env::set_var("USE_MONGODB", "false");
        assert!(!use_mongodb_env());
        std::env::remove_var("USE_MONGODB");
    }

    #[test]
    fn use_mongodb_env_invalid() {
        std::env::set_var("USE_MONGODB", "yes");
        assert!(!use_mongodb_env());
        std::env::remove_var("USE_MONGODB");
    }

    #[test]
    fn email_from_current_fields_propagated() {
        let current = super::CustomEmail::default();
        let email = email_from_current(&current);
        assert_eq!(email.id, current.email.id);
        assert_eq!(email.from, current.email.from);
        assert_eq!(email.to, current.email.to);
        assert_eq!(email.subject, current.email.subject);
        assert_eq!(email.body, current.email.body);
    }

    #[test]
    fn resolve_route_authenticated() {
        let manager = SessionManager::new();
        let session_id = manager.create_session("alice");
        manager.set_mailbox(&session_id, "INBOX");
        let result = resolve_route(Some(&session_id), &std::sync::Arc::new(manager), "bob@example.com");
        assert!(result.is_some());
        let (user, mbox) = result.unwrap();
        assert_eq!(user, "alice");
        assert_eq!(mbox, "INBOX");
    }

    #[test]
    fn resolve_route_unauthenticated() {
        use crate::smtp_server_dir::recipient::recipient_local_part;
        let manager = std::sync::Arc::new(SessionManager::new());
        let result = resolve_route(None, &manager, "alice@misfits.ai");
        assert!(result.is_some());
        let (user, mbox) = result.unwrap();
        assert_eq!(user, "alice");
        assert_eq!(mbox, "inbox");
    }

    #[test]
    fn resolve_route_authenticated_no_session() {
        let manager = std::sync::Arc::new(SessionManager::new());
        let result = resolve_route(Some("nonexistent"), &manager, "alice@misfits.ai");
        assert!(result.is_none());
    }
}

/// Persiste + forward un mail via MongoDB. Écrit la réponse SMTP appropriée.
pub(crate) async fn store_and_forward_mongo(
    stream: &mut StreamType,
    logic: &Arc<Logic>,
    session_manager: &Arc<SessionManager>,
    authenticated_session_id: Option<&String>,
    current: &CustomEmail,
) -> std::io::Result<()> {
    let email_to_store = email_from_current(current);
    let is_email_api_submission = current
        .raw_content
        .lines()
        .take_while(|line| !line.trim().is_empty())
        .any(|line| line.eq_ignore_ascii_case("X-Source-App: misfits-email-api"));

    // Authenticated SMTP submission: persist in sender Sent (never Inbox),
    // then deliver locally or forward externally.
    if let Some(session_id) = authenticated_session_id {
        let Some(sender_user) = session_manager.get_username(session_id) else {
            write_response(stream, "550 5.1.1 User unknown\r\n").await?;
            return Ok(());
        };

        if !is_email_api_submission {
            if let Err(e) = logic.store_email(&sender_user, "sent", &email_to_store).await {
                eprintln!("Failed to store sent email in MongoDB: {}", e);
                write_response(stream, "554 Transaction failed\r\n").await?;
                return Ok(());
            }

            let _ = logic
                .log_mail_event(
                    "sent",
                    &sender_user,
                    &email_to_store.id,
                    &email_to_store.subject,
                    &email_to_store.from,
                    &email_to_store.to,
                )
                .await;
        }

        if is_local_recipient(&email_to_store.to) {
            if let Some(recipient_user) = recipient_local_part(&email_to_store.to) {
                if let Err(e) = logic.store_email(&recipient_user, "inbox", &email_to_store).await {
                    eprintln!("Failed local inbox delivery in MongoDB: {}", e);
                    write_response(stream, "554 Transaction failed\r\n").await?;
                    return Ok(());
                }
                let _ = logic
                    .log_mail_event(
                        "received",
                        &recipient_user,
                        &email_to_store.id,
                        &email_to_store.subject,
                        &email_to_store.from,
                        &email_to_store.to,
                    )
                    .await;
            }
            write_response(stream, "250 OK\r\n").await?;
            return Ok(());
        }

        match send_outgoing_email(&email_to_store).await {
            Ok(_) => {
                write_response(stream, "250 OK\r\n").await?;
            }
            Err(e) => {
                error!("Failed to forward authenticated email: {}", e);
                write_response(
                    stream,
                    "451 4.4.0 Temporary forwarding failure\r\n",
                )
                .await?;
            }
        }
        return Ok(());
    }

    // Unauthenticated inbound SMTP (MX): route strictly to local inbox.
    let Some((user, mbox)) = resolve_route(None, session_manager, &email_to_store.to) else {
        eprintln!(
            "No routeable mailbox for recipient {}; refusing",
            email_to_store.to
        );
        write_response(stream, "550 5.1.1 User unknown\r\n").await?;
        return Ok(());
    };

    if let Err(e) = logic.store_email(&user, &mbox, &email_to_store).await {
        eprintln!("Failed to store email in MongoDB: {}", e);
        write_response(stream, "554 Transaction failed\r\n").await?;
        return Ok(());
    }

    let _ = logic
        .log_mail_event(
            "received",
            &user,
            &email_to_store.id,
            &email_to_store.subject,
            &email_to_store.from,
            &email_to_store.to,
        )
        .await;
    write_response(stream, "250 OK\r\n").await?;
    Ok(())
}

/// Traite une ligne de données entrantes (headers puis corps).
pub(crate) fn absorb_data_line(
    current: &mut CustomEmail,
    in_body: &mut bool,
    line: &str,
) -> Result<(), HeaderParseReject> {
    if !*in_body {
        if line.trim().is_empty() {
            *in_body = true;
        } else {
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if !trimmed.is_empty() {
                apply_parsed_header(current, trimmed)?;
            }
        }
    } else {
        current.email.body.push_str(line);
    }

    Ok(())
}
