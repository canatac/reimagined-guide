//! Cœur d'une session SMTP: état commun + dispatch des commandes + finalisation DATA.
//! Extrait de session.rs (cycle 44 — LOC ≤ 250).
#![allow(unused_imports, dead_code)]

use std::sync::Arc;

use log::error;

use simple_smtp_server::entities::Email;
use simple_smtp_server::logic::Logic;
use simple_smtp_server::session::SessionManager;
use simple_smtp_server::smtp_client::send_outgoing_email;

use super::{
    CustomEmail, MailServer, StreamType, extract_email_content,
    extract_session_id_from_response, process_command, write_response,
    session_helpers::{store_and_forward_mongo, use_mongodb_env},
};

/// État commun d'une session en cours.
pub(crate) struct SessionState {
    pub(crate) in_data_mode: bool,
    pub(crate) in_body: bool,
    pub(crate) authenticated_session_id: Option<String>,
    pub(crate) current_email: CustomEmail,
    pub(crate) mail_server: Arc<MailServer>,
}

impl SessionState {
    pub(crate) fn new() -> Self {
        Self {
            in_data_mode: false,
            in_body: false,
            authenticated_session_id: None,
            current_email: CustomEmail {
                email: Email::new("", "", "", "", ""),
                raw_content: String::new(),
                dkim_signature: None,
            },
            mail_server: Arc::new(MailServer::new("./emails")),
        }
    }
}

/// Fin de la commande DATA : persiste (MongoDB ou local) et écrit la réponse.
pub(crate) async fn finish_data(
    state: &mut SessionState,
    stream: &mut StreamType,
    logic: &Arc<Logic>,
    session_manager: &Arc<SessionManager>,
    local_forward: bool,
) -> std::io::Result<()> {
    state.in_data_mode = false;
    if use_mongodb_env() {
        store_and_forward_mongo(
            stream,
            logic,
            session_manager,
            state.authenticated_session_id.as_ref(),
            &state.current_email,
        )
        .await?;
    } else if local_forward {
        state.mail_server.store_email(&state.current_email).await?;
        match send_outgoing_email(&state.current_email.email).await {
            Ok(_) => {
                write_response(stream, "250 OK\r\n").await?;
            }
            Err(e) => {
                error!("Failed to forward email: {}", e);
                write_response(stream, "451 4.4.0 Temporary forwarding failure\r\n").await?;
            }
        }
    } else if let Err(e) = state.mail_server.store_email(&state.current_email).await {
        eprintln!("Failed to store email locally: {}", e);
        write_response(stream, "451 Local error in processing\r\n").await?;
    } else {
        println!("Email stored successfully locally");
        write_response(stream, "250 OK\r\n").await?;
    }
    Ok(())
}

/// Traite une commande SMTP hors DATA. Retourne true si QUIT (loop must break).
pub(crate) async fn handle_command_line(
    state: &mut SessionState,
    stream: &mut StreamType,
    logic: &Arc<Logic>,
    session_manager: &Arc<SessionManager>,
    line: &str,
    quit_response: Option<&str>,
    log_extracted_body: bool,
) -> std::io::Result<bool> {
    let response = process_command(
        line,
        &mut state.current_email,
        stream,
        logic.clone(),
        session_manager.clone(),
    )
    .await?;
    println!("Response: {}", response);
    if line.trim().to_ascii_uppercase().starts_with("AUTH ") && response.starts_with("235") {
        state.authenticated_session_id = extract_session_id_from_response(&response);
    }
    write_response(stream, &response).await?;

    if line.trim().eq_ignore_ascii_case("DATA") {
        state.in_data_mode = true;
    } else if line.trim().eq_ignore_ascii_case("QUIT") {
        if log_extracted_body {
            if let Ok(content) = extract_email_content(&state.current_email.email.body) {
                println!("Extracted email content: {}", content);
            } else {
                eprintln!("Error extracting email content");
            }
        }
        if let Some(bye) = quit_response {
            write_response(stream, bye).await?;
        }
        return Ok(true);
    }
    Ok(false)
}
