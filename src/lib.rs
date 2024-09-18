pub mod smtp_client;
pub use smtp_client::send_outgoing_email;
pub use smtp_client::extract_email_address;