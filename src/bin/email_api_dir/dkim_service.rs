use super::*;

#[async_trait::async_trait]
pub trait DkimService: Send + Sync {
    async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error>;
}

pub struct RealDkimService;

#[async_trait::async_trait]
impl DkimService for RealDkimService {
    async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error> {
        let dkim_service_url = env::var("DKIM_SERVICE_URL").map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "DKIM_SERVICE_URL not set")
        })?;
        let client = reqwest::Client::new();

        let response = client
            .post(&dkim_service_url)
            .json(&serde_json::json!({
                "from": email.from,
                "to": email.to,
                "subject": email.subject,
                "text": email.body,
                "html": email.body,
                "attachments": email.attachments.iter().map(|att| serde_json::json!({
                    "filename": att.filename,
                    "contentType": att.content_type,
                    "dataBase64": att.data_base64,
                })).collect::<Vec<_>>()
            }))
            .send()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        if status.is_success() {
            serde_json::from_str::<serde_json::Value>(&body)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        } else {
            let snippet = if body.len() > 1200 {
                &body[..1200]
            } else {
                &body
            };
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("DKIM service HTTP {}: {}", status.as_u16(), snippet),
            ))
        }
    }
}
