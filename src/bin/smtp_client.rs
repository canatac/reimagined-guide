use simple_smtp_server::smtp_client;
use simple_smtp_server::send_outgoing_email;
use simple_smtp_server::extract_email_address;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Your client main function implementation
    // You can call smtp_client::send_outgoing_email here
    Ok(())
}