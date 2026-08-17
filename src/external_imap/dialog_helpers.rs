//! Helpers extracted from dialog.rs to keep it under the LOC budget.

use openssl::ssl::{SslConnector, SslMethod};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::dialog::{run_imap_dialog_plain, run_imap_dialog_ssl};

pub(crate) fn imap_probe(
    host: &str,
    port: u16,
    use_tls: bool,
    username: &str,
    password: &str,
    include_list: bool,
) -> std::result::Result<(String, Vec<String>, Vec<String>), String> {
    if password.is_empty() {
        return Err("Missing credential secretValue on external account".to_string());
    }

    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve failed: {e}"))?
        .next()
        .ok_or_else(|| "resolve failed: no address".to_string())?;

    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| format!("tcp connect failed: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(12))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(12))).ok();

    if use_tls {
        let connector = SslConnector::builder(SslMethod::tls())
            .map_err(|e| format!("tls builder failed: {e}"))?
            .build();
        let ssl = connector
            .connect(host, tcp)
            .map_err(|e| format!("tls connect failed: {e}"))?;
        run_imap_dialog_ssl(ssl, username, password, include_list)
    } else {
        run_imap_dialog_plain(tcp, username, password, include_list)
    }
}
