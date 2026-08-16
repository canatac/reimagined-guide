//! MailServer struct + write_response + env_bool (refactor cycle 21).
#![allow(dead_code)]

use chrono::Utc;
use std::env;
use std::fs;
use std::path::Path;
use tokio::io::AsyncWriteExt;

use super::stream_helpers::StreamType;
use super::CustomEmail;

pub(crate) fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(raw) => {
            let v = raw.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
                || (!matches!(v.as_str(), "0" | "false" | "no" | "off") && default)
        }
        Err(_) => default,
    }
}

pub(crate) struct MailServer {
    pub(crate) mail_dir: String,
}

impl MailServer {
    pub(crate) fn new(mail_dir: &str) -> Self {
        fs::create_dir_all(mail_dir).unwrap();
        MailServer {
            mail_dir: mail_dir.to_string(),
        }
    }

    pub(crate) async fn store_email(&self, email: &CustomEmail) -> std::io::Result<()> {
        let timestamp = Utc::now().format("%Y%m%d%H%M%S");
        let filename = format!("{}-{}.eml", timestamp, email.email.to.replace("@", "_at_"));
        let path = Path::new(&self.mail_dir).join(filename);

        let mut file = tokio::fs::File::create(path).await?;
        file.write_all(format!("From: {}\r\n", email.email.from).as_bytes())
            .await?;
        file.write_all(format!("To: {}\r\n", email.email.to).as_bytes())
            .await?;
        file.write_all(format!("Subject: {}\r\n\r\n", email.email.subject).as_bytes())
            .await?;
        file.write_all(email.email.body.as_bytes()).await?;

        Ok(())
    }
}

pub(crate) async fn write_response(stream: &mut StreamType, response: &str) -> std::io::Result<()> {
    match stream {
        StreamType::Tls(ref mut s) => {
            s.write_all(response.as_bytes()).await?;
            s.flush().await
        }
        StreamType::Plain(ref mut s) => {
            s.write_all(response.as_bytes()).await?;
            s.flush().await
        }
    }
}
