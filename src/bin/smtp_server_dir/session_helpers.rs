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

/// Persiste + forward un mail via MongoDB. Écrit la réponse SMTP appropriée.
pub(crate) async fn store_and_forward_mongo(
    stream: &mut StreamType,
    logic: &Arc<Logic>,
    session_manager: &Arc<SessionManager>,
    authenticated_session_id: Option<&String>,
    current: &CustomEmail,
) -> std::io::Result<()> {
    let email_to_store = email_from_current(current);
    let resolved_route = resolve_route(authenticated_session_id, session_manager, &email_to_store.to);

    let Some((user, mbox)) = resolved_route else {
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

    println!("Email stored successfully in MongoDB for {user}/{mbox}");
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

    if is_local_recipient(&email_to_store.to) {
        write_response(stream, "250 OK\r\n").await?;
    } else {
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
    }
    Ok(())
}

/// Traite une ligne de données entrantes (headers puis corps).
pub(crate) fn absorb_data_line(current: &mut CustomEmail, in_body: &mut bool, line: &str) {
    if !*in_body {
        if line.trim().is_empty() {
            *in_body = true;
        } else {
            let trimmed = line.trim_end_matches(|c| c == '\r' || c == '\n');
            if !trimmed.is_empty() {
                apply_parsed_header(current, trimmed);
            }
        }
    } else {
        current.email.body.push_str(line);
    }
}
