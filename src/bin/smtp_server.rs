use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::env;
use std::sync::Arc;
use chrono::Utc;
use log::{info, debug, error};
use dotenv::dotenv;
use constant_time_eq::constant_time_eq;

// Structures de données simplifiées
#[derive(Debug, Default)]
struct CustomEmail {
    from: String,
    to: Vec<String>,
    data: String,
    timestamp: String,
}

fn main() -> io::Result<()> {
    dotenv().ok();
    env_logger::init();
    
    // Configuration
    let plain_addr = env::var("SMTP_PLAIN_ADDR").unwrap_or_else(|_| "0.0.0.0:8025".to_string());
    let tls_addr = env::var("SMTP_TLS_ADDR").unwrap_or_else(|_| "0.0.0.0:8465".to_string());
    
    // Créer le dossier de stockage
    fs::create_dir_all("./emails")?;
    
    // Écouter sur le port plain
    let plain_listener = TcpListener::bind(&plain_addr)?;
    info!("SMTP Server (plain) listening on {}", plain_addr);
    
    // Écouter sur le port TLS (simulé, TLS géré par stunnel)
    let tls_listener = TcpListener::bind(&tls_addr)?;
    info!("SMTP Server (TLS) listening on {}", tls_addr);
    
    // Boucle principale
    for listener in [plain_listener, tls_listener].iter() {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if let Err(e) = handle_client(stream) {
                        error!("Error handling client: {}", e);
                    }
                }
                Err(e) => {
                    error!("Connection failed: {}", e);
                }
            }
        }
    }
    
    Ok(())
}

fn handle_client(mut stream: TcpStream) -> io::Result<()> {
    let mut buffer = [0; 1024];
    let mut email = CustomEmail::default();
    
    // Message de bienvenue
    stream.write_all(b"220 localhost SMTP server ready\r\n")?;
    
    loop {
        let n = stream.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        
        let command = String::from_utf8_lossy(&buffer[..n]);
        debug!("Received: {}", command.trim());
        
        if command.trim().eq_ignore_ascii_case("QUIT") {
            stream.write_all(b"221 Bye\r\n")?;
            break;
        } else if command.trim().starts_with("EHLO") || command.trim().starts_with("HELO") {
            stream.write_all(b"250 localhost Hello\r\n")?;
        } else if command.trim().starts_with("MAIL FROM:") {
            email.from = command.trim()[10..].trim().to_string();
            stream.write_all(b"250 OK\r\n")?;
        } else if command.trim().starts_with("RCPT TO:") {
            email.to.push(command.trim()[8..].trim().to_string());
            stream.write_all(b"250 OK\r\n")?;
        } else if command.trim() == "DATA" {
            stream.write_all(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")?;
            let mut email_data = Vec::new();
            loop {
                let n = stream.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                email_data.extend_from_slice(&buffer[..n]);
                if email_data.ends_with(b"\r\n.\r\n") {
                    break;
                }
            }
            email.data = String::from_utf8_lossy(&email_data).into_owned();
            email.timestamp = Utc::now().to_rfc3339();
            
            // Sauvegarder l'email
            let email_path = Path::new("./emails").join(format!("email_{}.eml", Utc::now().timestamp()));
            let mut file = File::create(email_path)?;
            file.write_all(email.data.as_bytes())?;
            
            stream.write_all(b"250 OK\r\n")?;
        } else if command.trim().starts_with("AUTH LOGIN") {
            handle_auth_login(&mut stream)?;
        } else {
            stream.write_all(b"500 Command not recognized\r\n")?;
        }
    }
    
    Ok(())
}

fn handle_auth_login(stream: &mut TcpStream) -> io::Result<()> {
    // Vérifier les credentials
    let expected_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set");
    let expected_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");
    
    // Envoyer le challenge
    stream.write_all(b"334 VXNlcm5hbWU6\r\n")?; // "Username:" en base64
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer)?;
    let username = base64::decode(&buffer[..n].trim_end()).unwrap();
    
    stream.write_all(b"334 UGFzc3dvcmQ6\r\n")?; // "Password:" en base64
    let n = stream.read(&mut buffer)?;
    let password = base64::decode(&buffer[..n].trim_end()).unwrap();
    
    // Vérifier les credentials
    let username_match = constant_time_eq(&username, expected_username.as_bytes());
    let password_match = constant_time_eq(&password, expected_password.as_bytes());
    
    if username_match && password_match {
        stream.write_all(b"235 Authentication successful\r\n")?;
    } else {
        stream.write_all(b"535 Authentication failed\r\n")?;
    }
    
    Ok(())
}