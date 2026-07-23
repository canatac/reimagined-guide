use chrono::Utc;
use clap::{App, Arg};
use dotenv::dotenv;
use simple_smtp_server::entities::Email;
use simple_smtp_server::smtp_client::send_outgoing_email;
use uuid::Uuid;

fn validate_email_content(content: &str) -> Result<(), String> {
    let lines: Vec<&str> = content.lines().collect();
    if !lines[0].starts_with("From: <") || !lines[0].ends_with(">") {
        return Err("Invalid From header".to_string());
    }
    if !lines[1].starts_with("To: <") || !lines[1].ends_with(">") {
        return Err("Invalid To header".to_string());
    }
    if !lines[2].starts_with("Subject: ") {
        return Err("Invalid Subject header".to_string());
    }
    if lines[3] != "" {
        return Err("Missing blank line after headers".to_string());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    let matches = App::new("Email Sender")
        .version("1.0")
        .author("Your Name")
        .about("Sends emails via SMTP")
        .arg(
            Arg::with_name("from")
                .short('f')
                .long("from")
                .value_name("FROM")
                .help("Sets the sender email address")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("to")
                .short('t')
                .long("to")
                .value_name("TO")
                .help("Sets the recipient email address")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("subject")
                .short('s')
                .long("subject")
                .value_name("SUBJECT")
                .help("Sets the email subject")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("body")
                .short('b')
                .long("body")
                .value_name("BODY")
                .help("Sets the email body")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    let from = matches.value_of("from").unwrap();
    let to = matches.value_of("to").unwrap();
    let subject = matches.value_of("subject").unwrap();
    let body = matches.value_of("body").unwrap();

    let email_content = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\n\r\n{}",
        from, to, subject, body
    );

    if let Err(e) = validate_email_content(&email_content) {
        eprintln!("Invalid email content: {}", e);
        return Ok(());
    }

    let email = Email {
        id: Uuid::new_v4().to_string(),
        from: from.to_string(),
        to: to.to_string(),
        subject: subject.to_string(),
        body: body.to_string(),
        headers: vec![],
        flags: vec![],
        sequence_number: 0,
        uid: 0,
        internal_date: Utc::now(),
        dkim_signature: None,
    };

    match send_outgoing_email(&email).await {
        Ok(_) => println!("Email sent successfully"),
        Err(e) => eprintln!("Error sending email: {}", e),
    }

    Ok(())
}
