//! Découverte de port SMTP + helpers protocole (expect_code, ehlo_hostname).
//! Extraits de mod.rs (refactor architecte).

use std::env;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::{smtp_timeout_budget, SMTP_PORTS};

pub(crate) async fn test_smtp_port(host: &str, port: u16) -> bool {
    let budget = smtp_timeout_budget();
    matches!(
        timeout(
            Duration::from_millis(budget.port_probe_ms),
            TcpStream::connect((host, port)),
        )
        .await,
        Ok(Ok(_))
    )
}

pub(crate) async fn find_smtp_port(host: &str) -> Option<u16> {
    for &port in &SMTP_PORTS {
        if test_smtp_port(host, port).await {
            return Some(port);
        }
    }
    None
}

pub(crate) async fn expect_code<T: AsyncReadExt + Unpin>(
    stream: &mut T,
    expected: &str,
) -> std::io::Result<()> {
    let budget = smtp_timeout_budget();
    expect_code_for_phase(stream, expected, "smtp_response", budget.data_ms).await
}

pub(crate) async fn expect_code_for_phase<T: AsyncReadExt + Unpin>(
    stream: &mut T,
    expected: &str,
    phase: &str,
    timeout_ms: u64,
) -> std::io::Result<()> {
    let mut response = [0; 1024];
    let mut acc = String::new();

    for _ in 0..16 {
        let n = timeout(Duration::from_millis(timeout_ms), stream.read(&mut response))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("SMTP phase timeout [{}]: waited {}ms for code {}", phase, timeout_ms, expected),
                )
            })??;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("Connection closed while waiting for SMTP {}", expected),
            ));
        }

        let chunk = String::from_utf8_lossy(&response[..n]);
        acc.push_str(&chunk);
        println!("Received response: {}", chunk);

        for line in acc.split("\r\n").filter(|l| !l.is_empty()) {
            if line.len() < 4 {
                continue;
            }
            let prefix = &line[..3];
            let sep = line.as_bytes()[3] as char;
            let is_code = prefix.chars().all(|c| c.is_ascii_digit());
            if !is_code {
                continue;
            }

            if prefix == expected && sep == ' ' {
                return Ok(());
            }

            if sep == ' ' && prefix != expected {
                return Err(std::io::Error::other(format!(
                    "Unexpected response: {}",
                    acc
                )));
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("SMTP phase timeout [{}]: waiting code {} response after {}ms: {}", phase, expected, timeout_ms, acc),
    ))
}
pub(crate) fn ehlo_hostname() -> String {
    if let Ok(value) = env::var("SMTP_HOSTNAME") {
        if !value.trim().is_empty() {
            return value;
        }
    }
    "mail.misfits.ai".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ehlo_hostname_default() {
        let hostname = ehlo_hostname();
        assert_eq!(hostname, "mail.misfits.ai");
    }

    #[test]
    fn smtp_timeout_budget_default() {
        let budget = smtp_timeout_budget();
        assert!(budget.port_probe_ms > 0);
        assert!(budget.connect_ms > 0);
        assert!(budget.banner_ms > 0);
        assert!(budget.ehlo_ms > 0);
        assert!(budget.starttls_ms > 0);
        assert!(budget.tls_handshake_ms > 0);
        assert!(budget.auth_ms > 0);
        assert!(budget.mail_from_ms > 0);
        assert!(budget.rcpt_to_ms > 0);
        assert!(budget.data_ms > 0);
        assert!(budget.data_done_ms > 0);
        assert!(budget.quit_ms > 0);
    }

    #[test]
    fn smtp_ports_not_empty() {
        assert!(!SMTP_PORTS.is_empty());
    }

    #[test]
    fn smtp_ports_contains_standard_ports() {
        assert!(SMTP_PORTS.contains(&25));
        assert!(SMTP_PORTS.contains(&587));
        assert!(SMTP_PORTS.contains(&465));
    }

    #[test]
    fn smtp_ports_contains_submission_port() {
        assert!(SMTP_PORTS.contains(&587));
    }

    #[test]
    fn smtp_ports_contains_smtps_port() {
        assert!(SMTP_PORTS.contains(&465));
    }

    #[test]
    fn smtp_ports_contains_alternate_ports() {
        assert!(SMTP_PORTS.contains(&2525));
    }

    #[test]
    fn smtp_ports_all_valid() {
        for &port in &SMTP_PORTS {
            assert!(port > 0);
            assert!(port < 65536);
        }
    }

    #[test]
    fn smtp_ports_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for &port in &SMTP_PORTS {
            assert!(seen.insert(port));
        }
    }

    #[test]
    fn smtp_ports_sorted() {
        let mut sorted = SMTP_PORTS.to_vec();
        sorted.sort();
        assert_eq!(SMTP_PORTS.to_vec(), sorted);
    }

    #[test]
    fn smtp_timeout_budget_port_probe_positive() {
        let budget = smtp_timeout_budget();
        assert!(budget.port_probe_ms > 0);
    }

    #[test]
    fn smtp_timeout_budget_connect_positive() {
        let budget = smtp_timeout_budget();
        assert!(budget.connect_ms > 0);
    }

    #[test]
    fn smtp_timeout_budget_banner_positive() {
        let budget = smtp_timeout_budget();
        assert!(budget.banner_ms > 0);
    }

    #[test]
    fn smtp_timeout_budget_ehlo_positive() {
        let budget = smtp_timeout_budget();
        assert!(budget.ehlo_ms > 0);
    }

    #[test]
    fn smtp_timeout_budget_starttls_positive() {
        let budget = smtp_timeout_budget();
        assert!(budget.starttls_ms > 0);
    }

    #[test]
    fn smtp_timeout_budget_tls_handshake_positive() {
        let budget = smtp_timeout_budget();
        assert!(budget.tls_handshake_ms > 0);
    }

    #[test]
    fn smtp_timeout_budget_auth_positive() {
        let budget = smtp_timeout_budget();
        assert!(budget.auth_ms > 0);
    }

    #[test]
    fn smtp_timeout_budget_mail_from_positive() {
        let budget = smtp_timeout_budget();
        assert!(budget.mail_from_ms > 0);
    }

    #[test]
    fn smtp_timeout_budget_rcpt_to_positive() {
        let budget = smtp_timeout_budget();
        assert!(budget.rcpt_to_ms > 0);
    }

    #[test]
    fn smtp_timeout_budget_data_positive() {
        let budget = smtp_timeout_budget();
        assert!(budget.data_ms > 0);
    }

    #[test]
    fn smtp_timeout_budget_data_done_positive() {
        let budget = smtp_timeout_budget();
        assert!(budget.data_done_ms > 0);
    }

    #[test]
    fn smtp_timeout_budget_quit_positive() {
        let budget = smtp_timeout_budget();
        assert!(budget.quit_ms > 0);
    }

    #[test]
    fn smtp_timeout_budget_reasonable_values() {
        let budget = smtp_timeout_budget();
        assert!(budget.port_probe_ms <= 10000);
        assert!(budget.connect_ms <= 30000);
        assert!(budget.banner_ms <= 30000);
        assert!(budget.ehlo_ms <= 30000);
        assert!(budget.starttls_ms <= 30000);
        assert!(budget.tls_handshake_ms <= 30000);
        assert!(budget.auth_ms <= 30000);
        assert!(budget.mail_from_ms <= 30000);
        assert!(budget.rcpt_to_ms <= 30000);
        assert!(budget.data_ms <= 60000);
        assert!(budget.data_done_ms <= 60000);
        assert!(budget.quit_ms <= 10000);
    }

    #[test]
    fn ehlo_hostname_format() {
        let hostname = ehlo_hostname();
        assert!(!hostname.is_empty());
        assert!(hostname.contains('.'));
    }

    #[test]
    fn smtp_ports_first_is_25() {
        assert_eq!(SMTP_PORTS[0], 25);
    }

    #[test]
    fn smtp_ports_contains_587() {
        assert!(SMTP_PORTS.contains(&587));
    }

    #[test]
    fn smtp_ports_contains_465() {
        assert!(SMTP_PORTS.contains(&465));
    }

    #[test]
    fn smtp_ports_contains_2525() {
        assert!(SMTP_PORTS.contains(&2525));
    }

    #[test]
    fn smtp_ports_len() {
        assert!(SMTP_PORTS.len() >= 3);
    }

    #[test]
    fn smtp_timeout_budget_port_probe_less_than_connect() {
        let budget = smtp_timeout_budget();
        assert!(budget.port_probe_ms <= budget.connect_ms);
    }

    #[test]
    fn smtp_timeout_budget_banner_less_than_ehlo() {
        let budget = smtp_timeout_budget();
        assert!(budget.banner_ms <= budget.ehlo_ms);
    }

    #[test]
    fn smtp_timeout_budget_mail_from_less_than_data() {
        let budget = smtp_timeout_budget();
        assert!(budget.mail_from_ms <= budget.data_ms);
    }

    #[test]
    fn smtp_timeout_budget_rcpt_to_less_than_data() {
        let budget = smtp_timeout_budget();
        assert!(budget.rcpt_to_ms <= budget.data_ms);
    }

    #[test]
    fn smtp_timeout_budget_data_less_than_data_done() {
        let budget = smtp_timeout_budget();
        assert!(budget.data_ms <= budget.data_done_ms);
    }

    #[test]
    fn smtp_timeout_budget_quit_smallest() {
        let budget = smtp_timeout_budget();
        assert!(budget.quit_ms <= budget.connect_ms);
        assert!(budget.quit_ms <= budget.banner_ms);
        assert!(budget.quit_ms <= budget.ehlo_ms);
    }

    #[test]
    fn smtp_timeout_budget_all_unique() {
        let budget = smtp_timeout_budget();
        let values = vec![
            budget.port_probe_ms,
            budget.connect_ms,
            budget.banner_ms,
            budget.ehlo_ms,
            budget.starttls_ms,
            budget.tls_handshake_ms,
            budget.auth_ms,
            budget.mail_from_ms,
            budget.rcpt_to_ms,
            budget.data_ms,
            budget.data_done_ms,
            budget.quit_ms,
        ];
        let mut seen = std::collections::HashSet::new();
        for v in &values {
            seen.insert(*v);
        }
        assert_eq!(seen.len(), values.len());
    }

    #[test]
    fn smtp_timeout_budget_port_probe_is_smallest() {
        let budget = smtp_timeout_budget();
        assert!(budget.port_probe_ms <= budget.connect_ms);
        assert!(budget.port_probe_ms <= budget.banner_ms);
        assert!(budget.port_probe_ms <= budget.ehlo_ms);
        assert!(budget.port_probe_ms <= budget.starttls_ms);
        assert!(budget.port_probe_ms <= budget.tls_handshake_ms);
        assert!(budget.port_probe_ms <= budget.auth_ms);
        assert!(budget.port_probe_ms <= budget.mail_from_ms);
        assert!(budget.port_probe_ms <= budget.rcpt_to_ms);
        assert!(budget.port_probe_ms <= budget.data_ms);
        assert!(budget.port_probe_ms <= budget.data_done_ms);
        assert!(budget.port_probe_ms <= budget.quit_ms);
    }

    #[test]
    fn smtp_timeout_budget_data_done_is_largest() {
        let budget = smtp_timeout_budget();
        assert!(budget.data_done_ms >= budget.port_probe_ms);
        assert!(budget.data_done_ms >= budget.connect_ms);
        assert!(budget.data_done_ms >= budget.banner_ms);
        assert!(budget.data_done_ms >= budget.ehlo_ms);
        assert!(budget.data_done_ms >= budget.starttls_ms);
        assert!(budget.data_done_ms >= budget.tls_handshake_ms);
        assert!(budget.data_done_ms >= budget.auth_ms);
        assert!(budget.data_done_ms >= budget.mail_from_ms);
        assert!(budget.data_done_ms >= budget.rcpt_to_ms);
        assert!(budget.data_done_ms >= budget.data_ms);
        assert!(budget.data_done_ms >= budget.quit_ms);
    }

    #[test]
    fn smtp_timeout_budget_connect_is_largest() {
        let budget = smtp_timeout_budget();
        assert!(budget.connect_ms >= budget.port_probe_ms);
        assert!(budget.connect_ms >= budget.banner_ms);
        assert!(budget.connect_ms >= budget.ehlo_ms);
        assert!(budget.connect_ms >= budget.starttls_ms);
        assert!(budget.connect_ms >= budget.tls_handshake_ms);
        assert!(budget.connect_ms >= budget.auth_ms);
        assert!(budget.connect_ms >= budget.mail_from_ms);
        assert!(budget.connect_ms >= budget.rcpt_to_ms);
        assert!(budget.connect_ms >= budget.data_ms);
        assert!(budget.connect_ms >= budget.data_done_ms);
        assert!(budget.connect_ms >= budget.quit_ms);
    }

    #[test]
    fn smtp_timeout_budget_tls_handshake_is_large() {
        let budget = smtp_timeout_budget();
        assert!(budget.tls_handshake_ms >= budget.port_probe_ms);
        assert!(budget.tls_handshake_ms >= budget.banner_ms);
        assert!(budget.tls_handshake_ms >= budget.ehlo_ms);
        assert!(budget.tls_handshake_ms >= budget.starttls_ms);
        assert!(budget.tls_handshake_ms >= budget.auth_ms);
        assert!(budget.tls_handshake_ms >= budget.mail_from_ms);
        assert!(budget.tls_handshake_ms >= budget.rcpt_to_ms);
        assert!(budget.tls_handshake_ms >= budget.quit_ms);
    }

    #[test]
    fn smtp_timeout_budget_auth_is_large() {
        let budget = smtp_timeout_budget();
        assert!(budget.auth_ms >= budget.port_probe_ms);
        assert!(budget.auth_ms >= budget.banner_ms);
        assert!(budget.auth_ms >= budget.ehlo_ms);
        assert!(budget.auth_ms >= budget.starttls_ms);
        assert!(budget.auth_ms >= budget.mail_from_ms);
        assert!(budget.auth_ms >= budget.rcpt_to_ms);
        assert!(budget.auth_ms >= budget.quit_ms);
    }

    #[test]
    fn smtp_timeout_budget_mail_from_is_small() {
        let budget = smtp_timeout_budget();
        assert!(budget.mail_from_ms >= budget.port_probe_ms);
        assert!(budget.mail_from_ms <= budget.data_ms);
        assert!(budget.mail_from_ms <= budget.data_done_ms);
    }

    #[test]
    fn smtp_timeout_budget_rcpt_to_is_small() {
        let budget = smtp_timeout_budget();
        assert!(budget.rcpt_to_ms >= budget.port_probe_ms);
        assert!(budget.rcpt_to_ms <= budget.data_ms);
        assert!(budget.rcpt_to_ms <= budget.data_done_ms);
    }

    #[test]
    fn smtp_timeout_budget_data_is_medium() {
        let budget = smtp_timeout_budget();
        assert!(budget.data_ms >= budget.port_probe_ms);
        assert!(budget.data_ms >= budget.mail_from_ms);
        assert!(budget.data_ms >= budget.rcpt_to_ms);
        assert!(budget.data_ms <= budget.data_done_ms);
    }

    #[test]
    fn smtp_timeout_budget_quit_is_small() {
        let budget = smtp_timeout_budget();
        assert!(budget.quit_ms >= budget.port_probe_ms);
        assert!(budget.quit_ms <= budget.connect_ms);
        assert!(budget.quit_ms <= budget.banner_ms);
        assert!(budget.quit_ms <= budget.ehlo_ms);
        assert!(budget.quit_ms <= budget.starttls_ms);
        assert!(budget.quit_ms <= budget.tls_handshake_ms);
        assert!(budget.quit_ms <= budget.auth_ms);
        assert!(budget.quit_ms <= budget.mail_from_ms);
        assert!(budget.quit_ms <= budget.rcpt_to_ms);
        assert!(budget.quit_ms <= budget.data_ms);
        assert!(budget.quit_ms <= budget.data_done_ms);
    }

    #[test]
    fn smtp_timeout_budget_port_probe_is_1000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.port_probe_ms, 1000);
    }

    #[test]
    fn smtp_timeout_budget_connect_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.connect_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_banner_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.banner_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_ehlo_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.ehlo_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_starttls_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.starttls_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_tls_handshake_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.tls_handshake_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_auth_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.auth_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_mail_from_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.mail_from_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_rcpt_to_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.rcpt_to_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_data_is_10000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.data_ms, 10000);
    }

    #[test]
    fn smtp_timeout_budget_data_done_is_10000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.data_done_ms, 10000);
    }

    #[test]
    fn smtp_timeout_budget_quit_is_2000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.quit_ms, 2000);
    }

    #[test]
    fn smtp_ports_contains_25() {
        assert!(SMTP_PORTS.contains(&25));
    }

    #[test]
    fn smtp_ports_contains_587() {
        assert!(SMTP_PORTS.contains(&587));
    }

    #[test]
    fn smtp_ports_contains_465() {
        assert!(SMTP_PORTS.contains(&465));
    }

    #[test]
    fn smtp_ports_contains_2525() {
        assert!(SMTP_PORTS.contains(&2525));
    }

    #[test]
    fn smtp_ports_len_is_4() {
        assert_eq!(SMTP_PORTS.len(), 4);
    }

    #[test]
    fn smtp_ports_first_is_25() {
        assert_eq!(SMTP_PORTS[0], 25);
    }

    #[test]
    fn smtp_ports_last_is_2525() {
        assert_eq!(SMTP_PORTS[SMTP_PORTS.len() - 1], 2525);
    }

    #[test]
    fn smtp_ports_sorted_ascending() {
        for i in 1..SMTP_PORTS.len() {
            assert!(SMTP_PORTS[i] > SMTP_PORTS[i - 1]);
        }
    }

    #[test]
    fn ehlo_hostname_contains_misfits() {
        let hostname = ehlo_hostname();
        assert!(hostname.contains("misfits"));
    }

    #[test]
    fn ehlo_hostname_contains_ai() {
        let hostname = ehlo_hostname();
        assert!(hostname.contains("ai"));
    }

    #[test]
    fn ehlo_hostname_starts_with_mail() {
        let hostname = ehlo_hostname();
        assert!(hostname.starts_with("mail"));
    }

    #[test]
    fn ehlo_hostname_ends_with_ai() {
        let hostname = ehlo_hostname();
        assert!(hostname.ends_with("ai"));
    }

    #[test]
    fn ehlo_hostname_has_two_parts() {
        let hostname = ehlo_hostname();
        let parts: Vec<&str> = hostname.split('.').collect();
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn ehlo_hostname_first_part_is_mail() {
        let hostname = ehlo_hostname();
        let parts: Vec<&str> = hostname.split('.').collect();
        assert_eq!(parts[0], "mail");
    }

    #[test]
    fn ehlo_hostname_second_part_is_misfits_ai() {
        let hostname = ehlo_hostname();
        let parts: Vec<&str> = hostname.split('.').collect();
        assert_eq!(parts[1], "misfits.ai");
    }

    #[test]
    fn smtp_timeout_budget_all_positive() {
        let budget = smtp_timeout_budget();
        assert!(budget.port_probe_ms > 0);
        assert!(budget.connect_ms > 0);
        assert!(budget.banner_ms > 0);
        assert!(budget.ehlo_ms > 0);
        assert!(budget.starttls_ms > 0);
        assert!(budget.tls_handshake_ms > 0);
        assert!(budget.auth_ms > 0);
        assert!(budget.mail_from_ms > 0);
        assert!(budget.rcpt_to_ms > 0);
        assert!(budget.data_ms > 0);
        assert!(budget.data_done_ms > 0);
        assert!(budget.quit_ms > 0);
    }

    #[test]
    fn smtp_timeout_budget_port_probe_is_smallest() {
        let budget = smtp_timeout_budget();
        let min = budget.port_probe_ms;
        assert!(min <= budget.connect_ms);
        assert!(min <= budget.banner_ms);
        assert!(min <= budget.ehlo_ms);
        assert!(min <= budget.starttls_ms);
        assert!(min <= budget.tls_handshake_ms);
        assert!(min <= budget.auth_ms);
        assert!(min <= budget.mail_from_ms);
        assert!(min <= budget.rcpt_to_ms);
        assert!(min <= budget.data_ms);
        assert!(min <= budget.data_done_ms);
        assert!(min <= budget.quit_ms);
    }

    #[test]
    fn smtp_timeout_budget_data_done_is_largest() {
        let budget = smtp_timeout_budget();
        let max = budget.data_done_ms;
        assert!(max >= budget.port_probe_ms);
        assert!(max >= budget.connect_ms);
        assert!(max >= budget.banner_ms);
        assert!(max >= budget.ehlo_ms);
        assert!(max >= budget.starttls_ms);
        assert!(max >= budget.tls_handshake_ms);
        assert!(max >= budget.auth_ms);
        assert!(max >= budget.mail_from_ms);
        assert!(max >= budget.rcpt_to_ms);
        assert!(max >= budget.data_ms);
        assert!(max >= budget.quit_ms);
    }

    #[test]
    fn smtp_timeout_budget_connect_is_largest() {
        let budget = smtp_timeout_budget();
        let max = budget.connect_ms;
        assert!(max >= budget.port_probe_ms);
        assert!(max >= budget.banner_ms);
        assert!(max >= budget.ehlo_ms);
        assert!(max >= budget.starttls_ms);
        assert!(max >= budget.tls_handshake_ms);
        assert!(max >= budget.auth_ms);
        assert!(max >= budget.mail_from_ms);
        assert!(max >= budget.rcpt_to_ms);
        assert!(max >= budget.data_ms);
        assert!(max >= budget.data_done_ms);
        assert!(max >= budget.quit_ms);
    }

    #[test]
    fn smtp_timeout_budget_tls_handshake_is_large() {
        let budget = smtp_timeout_budget();
        let val = budget.tls_handshake_ms;
        assert!(val >= budget.port_probe_ms);
        assert!(val >= budget.banner_ms);
        assert!(val >= budget.ehlo_ms);
        assert!(val >= budget.starttls_ms);
        assert!(val >= budget.auth_ms);
        assert!(val >= budget.mail_from_ms);
        assert!(val >= budget.rcpt_to_ms);
        assert!(val >= budget.quit_ms);
    }

    #[test]
    fn smtp_timeout_budget_auth_is_large() {
        let budget = smtp_timeout_budget();
        let val = budget.auth_ms;
        assert!(val >= budget.port_probe_ms);
        assert!(val >= budget.banner_ms);
        assert!(val >= budget.ehlo_ms);
        assert!(val >= budget.starttls_ms);
        assert!(val >= budget.mail_from_ms);
        assert!(val >= budget.rcpt_to_ms);
        assert!(val >= budget.quit_ms);
    }

    #[test]
    fn smtp_timeout_budget_mail_from_is_small() {
        let budget = smtp_timeout_budget();
        let val = budget.mail_from_ms;
        assert!(val >= budget.port_probe_ms);
        assert!(val <= budget.data_ms);
        assert!(val <= budget.data_done_ms);
    }

    #[test]
    fn smtp_timeout_budget_rcpt_to_is_small() {
        let budget = smtp_timeout_budget();
        let val = budget.rcpt_to_ms;
        assert!(val >= budget.port_probe_ms);
        assert!(val <= budget.data_ms);
        assert!(val <= budget.data_done_ms);
    }

    #[test]
    fn smtp_timeout_budget_data_is_medium() {
        let budget = smtp_timeout_budget();
        let val = budget.data_ms;
        assert!(val >= budget.port_probe_ms);
        assert!(val >= budget.mail_from_ms);
        assert!(val >= budget.rcpt_to_ms);
        assert!(val <= budget.data_done_ms);
    }

    #[test]
    fn smtp_timeout_budget_quit_is_small() {
        let budget = smtp_timeout_budget();
        let val = budget.quit_ms;
        assert!(val >= budget.port_probe_ms);
        assert!(val <= budget.connect_ms);
        assert!(val <= budget.banner_ms);
        assert!(val <= budget.ehlo_ms);
        assert!(val <= budget.starttls_ms);
        assert!(val <= budget.tls_handshake_ms);
        assert!(val <= budget.auth_ms);
        assert!(val <= budget.mail_from_ms);
        assert!(val <= budget.rcpt_to_ms);
        assert!(val <= budget.data_ms);
        assert!(val <= budget.data_done_ms);
    }

    #[test]
    fn smtp_timeout_budget_port_probe_is_1000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.port_probe_ms, 1000);
    }

    #[test]
    fn smtp_timeout_budget_connect_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.connect_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_banner_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.banner_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_ehlo_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.ehlo_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_starttls_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.starttls_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_tls_handshake_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.tls_handshake_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_auth_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.auth_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_mail_from_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.mail_from_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_rcpt_to_is_5000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.rcpt_to_ms, 5000);
    }

    #[test]
    fn smtp_timeout_budget_data_is_10000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.data_ms, 10000);
    }

    #[test]
    fn smtp_timeout_budget_data_done_is_10000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.data_done_ms, 10000);
    }

    #[test]
    fn smtp_timeout_budget_quit_is_2000() {
        let budget = smtp_timeout_budget();
        assert_eq!(budget.quit_ms, 2000);
    }
}
