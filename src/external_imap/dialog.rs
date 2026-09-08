//! Dialogues IMAP hand-rollés (extrait de mod.rs).

use chrono::Utc;
use openssl::ssl::{SslConnector, SslMethod, SslStream};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::parser::{
    escape_imap, parse_capabilities, parse_fetch_headers, parse_list_folders, parse_uid_search,
    read_line_from_stream, read_until_tag_from_stream, tag_status_ok, ImapFetchedHeader,
};

pub(crate) fn run_imap_dialog_plain(
    stream: TcpStream,
    username: &str,
    password: &str,
    include_list: bool,
) -> std::result::Result<(String, Vec<String>, Vec<String>), String> {
    run_imap_dialog(stream, username, password, include_list)
}

pub(crate) fn run_imap_dialog_ssl(
    stream: SslStream<TcpStream>,
    username: &str,
    password: &str,
    include_list: bool,
) -> std::result::Result<(String, Vec<String>, Vec<String>), String> {
    run_imap_dialog(stream, username, password, include_list)
}

fn run_imap_dialog<S: std::io::Read + std::io::Write>(
    mut stream: S,
    username: &str,
    password: &str,
    include_list: bool,
) -> std::result::Result<(String, Vec<String>, Vec<String>), String> {
    let greeting = read_line_from_stream(&mut stream)?;

    write_command(&mut stream, "a1 CAPABILITY\r\n", "CAPABILITY")?;
    let cap_lines = read_until_tag_from_stream(&mut stream, "a1")?;
    let capabilities = parse_capabilities(&cap_lines);

    let login = format!(
        "a2 LOGIN \"{}\" \"{}\"\r\n",
        escape_imap(username),
        escape_imap(password)
    );
    write_command(&mut stream, &login, "LOGIN")?;
    let login_lines = read_until_tag_from_stream(&mut stream, "a2")?;
    ensure_ok(&login_lines, "a2", "IMAP login failed")?;

    let folders = fetch_folders_if_requested(&mut stream, include_list)?;

    logout_best_effort(&mut stream);
    Ok((greeting, capabilities, folders))
}

pub(crate) fn imap_fetch_headers_since(
    host: &str,
    port: u16,
    use_tls: bool,
    username: &str,
    password: &str,
    folder: &str,
    since_imap: &str,
) -> std::result::Result<Vec<ImapFetchedHeader>, String> {
    ensure_password(password)?;
    let addr = resolve_addr(host, port)?;
    let tcp = connect_tcp_with_timeouts(&addr)?;

    if use_tls {
        let connector = SslConnector::builder(SslMethod::tls())
            .map_err(|e| format!("tls builder failed: {e}"))?
            .build();
        let ssl = connector
            .connect(host, tcp)
            .map_err(|e| format!("tls connect failed: {e}"))?;
        imap_fetch_dialog(ssl, username, password, folder, since_imap)
    } else {
        imap_fetch_dialog(tcp, username, password, folder, since_imap)
    }
}

fn ensure_password(password: &str) -> std::result::Result<(), String> {
    if password.is_empty() {
        Err("Missing credential secretValue on external account".to_string())
    } else {
        Ok(())
    }
}

fn resolve_addr(host: &str, port: u16) -> std::result::Result<std::net::SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve failed: {e}"))?
        .next()
        .ok_or_else(|| "resolve failed: no address".to_string())
}

fn connect_tcp_with_timeouts(addr: &std::net::SocketAddr) -> std::result::Result<TcpStream, String> {
    let tcp = TcpStream::connect_timeout(addr, Duration::from_secs(10))
        .map_err(|e| format!("tcp connect failed: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(30))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(30))).ok();
    Ok(tcp)
}

fn imap_fetch_dialog<S: std::io::Read + std::io::Write>(
    mut stream: S,
    username: &str,
    password: &str,
    folder: &str,
    since_imap: &str,
) -> std::result::Result<Vec<ImapFetchedHeader>, String> {
    let _greeting = read_line_from_stream(&mut stream)?;

    let login = format!(
        "a1 LOGIN \"{}\" \"{}\"\r\n",
        escape_imap(username),
        escape_imap(password)
    );
    send_and_expect_ok(&mut stream, &login, "LOGIN", "a1", "IMAP login failed")?;

    let select = format!("a2 SELECT \"{}\"\r\n", escape_imap(folder));
    send_and_expect_ok(
        &mut stream,
        &select,
        "SELECT",
        "a2",
        &format!("IMAP select {} failed", folder),
    )?;

    let search = format!("a3 UID SEARCH SINCE {}\r\n", since_imap);
    let search_lines = send_and_expect_ok_collect(
        &mut stream,
        &search,
        "SEARCH",
        "a3",
        "IMAP UID SEARCH failed",
    )?;

    let uids = parse_uid_search(&search_lines);
    if uids.is_empty() {
        logout_best_effort(&mut stream);
        return Ok(vec![]);
    }

    let mut result: Vec<ImapFetchedHeader> = Vec::new();
    for chunk in uids.chunks(200) {
        let set = chunk
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let fetch_cmd = format!(
            "a4 UID FETCH {} (UID INTERNALDATE FLAGS BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)])\r\n",
            set
        );
        let fetch_lines = send_and_expect_ok_collect(
            &mut stream,
            &fetch_cmd,
            "FETCH",
            "a4",
            "IMAP UID FETCH failed",
        )?;
        let mut parsed = parse_fetch_headers(&fetch_lines);
        result.append(&mut parsed);
    }

    logout_best_effort(&mut stream);
    Ok(result)
}

fn fetch_folders_if_requested<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    include_list: bool,
) -> std::result::Result<Vec<String>, String> {
    if !include_list {
        return Ok(vec![]);
    }

    write_command(stream, "a3 LIST \"\" \"*\"\r\n", "LIST")?;
    let list_lines = read_until_tag_from_stream(stream, "a3")?;
    Ok(parse_list_folders(&list_lines))
}

fn write_command<S: std::io::Write>(stream: &mut S, cmd: &str, label: &str) -> std::result::Result<(), String> {
    stream
        .write_all(cmd.as_bytes())
        .map_err(|e| format!("write {label} failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))
}

fn ensure_ok(lines: &[String], tag: &str, err_prefix: &str) -> std::result::Result<(), String> {
    if tag_status_ok(lines, tag) {
        Ok(())
    } else {
        Err(format!("{}: {}", err_prefix, lines.join(" | ")))
    }
}

fn send_and_expect_ok<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    cmd: &str,
    label: &str,
    tag: &str,
    err_prefix: &str,
) -> std::result::Result<(), String> {
    let lines = send_and_expect_ok_collect(stream, cmd, label, tag, err_prefix)?;
    ensure_ok(&lines, tag, err_prefix)
}

fn send_and_expect_ok_collect<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    cmd: &str,
    label: &str,
    tag: &str,
    err_prefix: &str,
) -> std::result::Result<Vec<String>, String> {
    write_command(stream, cmd, label)?;
    let lines = read_until_tag_from_stream(stream, tag)?;
    ensure_ok(&lines, tag, err_prefix)?;
    Ok(lines)
}

fn logout_best_effort<S: std::io::Write>(stream: &mut S) {
    let _ = stream.write_all(b"a9 LOGOUT\r\n");
    let _ = stream.flush();
}

// Force Utc use to be referenced by the module for downstream re-exports
#[allow(dead_code)]
fn _touch_utc() -> chrono::DateTime<Utc> {
    Utc::now()
}
