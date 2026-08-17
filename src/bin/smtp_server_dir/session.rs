//! Boucles de session SMTP: connexions plain et TLS.
//! Extraites de smtp_server.rs (refactor architecte). Cycle 44: cœur déplacé dans session_core.rs.
#![allow(unused_imports, dead_code)]

use std::sync::Arc;

use log::{error, info};
use tokio::io::AsyncBufReadExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use simple_smtp_server::logic::Logic;
use simple_smtp_server::session::SessionManager;

use super::{
    StreamType, write_response,
    session_core::{SessionState, finish_data, handle_command_line},
    session_helpers::absorb_data_line,
};

// Handle TLS client connection
pub(crate) async fn handle_tls_client(
    tls_stream: TlsStream<TcpStream>,
    logic: Arc<Logic>,
    session_manager: Arc<SessionManager>,
) -> std::io::Result<()> {
    info!("TLS connection established");
    let _peer_addr = tls_stream.get_ref().0.peer_addr()?;
    let mut stream = StreamType::Tls(tokio::io::BufReader::new(tls_stream));

    let greeting = "220 mail.misfits.ai ESMTP\r\n";
    write_response(&mut stream, &greeting).await?;

    let mut state = SessionState::new();
    loop {
        let mut buffer = Vec::new();
        match stream.read_until(b'\n', &mut buffer).await {
            Ok(0) => {
                println!("TLS Client disconnected");
                break;
            }
            Ok(_) => {
                let line = String::from_utf8_lossy(&buffer).to_string();
                println!("Received: {}", line.trim());

                if line.trim().eq_ignore_ascii_case("STARTTLS") {
                    write_response(
                        &mut stream,
                        "454 TLS not available due to temporary reason\r\n",
                    )
                    .await?;
                    continue;
                }
                if state.in_data_mode {
                    if line.trim() == "." {
                        finish_data(&mut state, &mut stream, &logic, &session_manager, false).await?;
                    } else {
                        absorb_data_line(&mut state.current_email, &mut state.in_body, &line);
                    }
                } else {
                    let should_break = handle_command_line(
                        &mut state,
                        &mut stream,
                        &logic,
                        &session_manager,
                        &line,
                        None,
                        true,
                    )
                    .await?;
                    if should_break {
                        break;
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading from client: {}", e);
                break;
            }
        }
    }

    Ok(())
}

// Handle plain client connection
pub(crate) async fn handle_plain_client(
    stream: TcpStream,
    tls_acceptor: Arc<TlsAcceptor>,
    logic: Arc<Logic>,
    session_manager: Arc<SessionManager>,
) -> std::io::Result<()> {
    let peer_addr = stream.peer_addr()?;
    info!("New plain connection from: {}", peer_addr);
    let mut stream = StreamType::Plain(tokio::io::BufReader::new(stream));

    let greeting = "220 mail.misfits.ai ESMTP\r\n";
    info!("Sending greeting to {}: {}", peer_addr, greeting.trim());
    write_response(&mut stream, &greeting).await?;

    let mut state = SessionState::new();
    loop {
        let mut buffer = String::new();
        match stream.read_line(&mut buffer).await {
            Ok(0) => {
                println!("Client disconnected  : {}", buffer.trim());
                break;
            }
            Ok(_n) => {
                println!("Calling process_command with: {}", buffer.trim());
                if buffer.trim().eq_ignore_ascii_case("STARTTLS") {
                    write_response(&mut stream, "220 Ready to start TLS\r\n").await?;
                    match stream {
                        StreamType::Plain(plain_stream) => {
                            let tls_stream = tls_acceptor.accept(plain_stream.into_inner()).await?;
                            stream = StreamType::Tls(tokio::io::BufReader::new(tls_stream));
                            println!("Upgraded to TLS connection");
                        }
                        StreamType::Tls(_) => {
                            write_response(
                                &mut stream,
                                "454 TLS not available due to temporary reason\r\n",
                            )
                            .await?;
                        }
                    }
                    continue;
                }
                if state.in_data_mode {
                    println!("In in_data_mode");
                    if buffer.trim() == "." {
                        finish_data(&mut state, &mut stream, &logic, &session_manager, true).await?;
                    } else {
                        absorb_data_line(&mut state.current_email, &mut state.in_body, &buffer);
                    }
                } else {
                    let should_break = handle_command_line(
                        &mut state,
                        &mut stream,
                        &logic,
                        &session_manager,
                        &buffer,
                        Some("221 Bye\r\n"),
                        false,
                    )
                    .await?;
                    if should_break {
                        break;
                    }
                }
            }
            Err(e) => {
                error!("Error reading from client {}: {}", peer_addr, e);
                break;
            }
        }
    }

    Ok(())
}
