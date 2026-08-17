//! Dialogues IMAP hand-rollés (extrait de mod.rs).

use chrono::Utc;
use openssl::ssl::{SslConnector, SslMethod, SslStream};
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::parser::{
    escape_imap, parse_capabilities, parse_fetch_headers, parse_list_folders, parse_uid_search,
    read_line_from_stream, read_until_tag_from_stream, tag_status_ok, ImapFetchedHeader,
};

pub(crate) fn run_imap_dialog_plain(
    mut stream: TcpStream,
    username: &str,
    password: &str,
    include_list: bool,
) -> std::result::Result<(String, Vec<String>, Vec<String>), String> {
    let greeting = read_line_from_stream(&mut stream)?;

    stream
        .write_all(b"a1 CAPABILITY\r\n")
        .map_err(|e| format!("write CAPABILITY failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))?;
    let cap_lines = read_until_tag_from_stream(&mut stream, "a1")?;
    let capabilities = parse_capabilities(&cap_lines);

    let login = format!("a2 LOGIN \"{}\" \"{}\"\r\n", escape_imap(username), escape_imap(password));
    stream
        .write_all(login.as_bytes())
        .map_err(|e| format!("write LOGIN failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))?;
    let login_lines = read_until_tag_from_stream(&mut stream, "a2")?;
    if !tag_status_ok(&login_lines, "a2") {
        return Err(format!("IMAP login failed: {}", login_lines.join(" | ")));
    }

    let mut folders = vec![];
    if include_list {
        stream
            .write_all(b"a3 LIST \"\" \"*\"\r\n")
            .map_err(|e| format!("write LIST failed: {e}"))?;
        stream.flush().map_err(|e| format!("flush failed: {e}"))?;
        let list_lines = read_until_tag_from_stream(&mut stream, "a3")?;
        folders = parse_list_folders(&list_lines);
    }

    let _ = stream.write_all(b"a9 LOGOUT\r\n");
    let _ = stream.flush();

    Ok((greeting, capabilities, folders))
}

pub(crate) fn run_imap_dialog_ssl(
    mut stream: SslStream<TcpStream>,
    username: &str,
    password: &str,
    include_list: bool,
) -> std::result::Result<(String, Vec<String>, Vec<String>), String> {
    let greeting = read_line_from_stream(&mut stream)?;

    stream
        .write_all(b"a1 CAPABILITY\r\n")
        .map_err(|e| format!("write CAPABILITY failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))?;
    let cap_lines = read_until_tag_from_stream(&mut stream, "a1")?;
    let capabilities = parse_capabilities(&cap_lines);

    let login = format!("a2 LOGIN \"{}\" \"{}\"\r\n", escape_imap(username), escape_imap(password));
    stream
        .write_all(login.as_bytes())
        .map_err(|e| format!("write LOGIN failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))?;
    let login_lines = read_until_tag_from_stream(&mut stream, "a2")?;
    if !tag_status_ok(&login_lines, "a2") {
        return Err(format!("IMAP login failed: {}", login_lines.join(" | ")));
    }

    let mut folders = vec![];
    if include_list {
        stream
            .write_all(b"a3 LIST \"\" \"*\"\r\n")
            .map_err(|e| format!("write LIST failed: {e}"))?;
        stream.flush().map_err(|e| format!("flush failed: {e}"))?;
        let list_lines = read_until_tag_from_stream(&mut stream, "a3")?;
        folders = parse_list_folders(&list_lines);
    }

    let _ = stream.write_all(b"a9 LOGOUT\r\n");
    let _ = stream.flush();

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
    tcp.set_read_timeout(Some(Duration::from_secs(30))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(30))).ok();

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
    stream
        .write_all(login.as_bytes())
        .map_err(|e| format!("write LOGIN failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))?;
    let login_lines = read_until_tag_from_stream(&mut stream, "a1")?;
    if !tag_status_ok(&login_lines, "a1") {
        return Err(format!("IMAP login failed: {}", login_lines.join(" | ")));
    }

    let sel = format!("a2 SELECT \"{}\"\r\n", escape_imap(folder));
    stream
        .write_all(sel.as_bytes())
        .map_err(|e| format!("write SELECT failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))?;
    let sel_lines = read_until_tag_from_stream(&mut stream, "a2")?;
    if !tag_status_ok(&sel_lines, "a2") {
        return Err(format!(
            "IMAP select {} failed: {}",
            folder,
            sel_lines.join(" | ")
        ));
    }

    let search = format!("a3 UID SEARCH SINCE {}\r\n", since_imap);
    stream
        .write_all(search.as_bytes())
        .map_err(|e| format!("write SEARCH failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))?;
    let search_lines = read_until_tag_from_stream(&mut stream, "a3")?;
    if !tag_status_ok(&search_lines, "a3") {
        return Err(format!(
            "IMAP UID SEARCH failed: {}",
            search_lines.join(" | ")
        ));
    }
    let uids = parse_uid_search(&search_lines);
    if uids.is_empty() {
        let _ = stream.write_all(b"a9 LOGOUT\r\n");
        let _ = stream.flush();
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
        stream
            .write_all(fetch_cmd.as_bytes())
            .map_err(|e| format!("write FETCH failed: {e}"))?;
        stream.flush().map_err(|e| format!("flush failed: {e}"))?;
        let fetch_lines = read_until_tag_from_stream(&mut stream, "a4")?;
        if !tag_status_ok(&fetch_lines, "a4") {
            return Err(format!(
                "IMAP UID FETCH failed: {}",
                fetch_lines.join(" | ")
            ));
        }
        let mut parsed = parse_fetch_headers(&fetch_lines);
        result.append(&mut parsed);
    }

    let _ = stream.write_all(b"a9 LOGOUT\r\n");
    let _ = stream.flush();
    Ok(result)
}

// Force Utc use to be referenced by the module for downstream re-exports
#[allow(dead_code)]
fn _touch_utc() -> chrono::DateTime<Utc> {
    Utc::now()
}
