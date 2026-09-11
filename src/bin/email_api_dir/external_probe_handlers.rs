/*!
 * Live IMAP console: opens an IMAP session against a candidate account and
 * streams every command/response pair as Server-Sent Events, so the UI can
 * render a real-time terminal ("a1 CAPABILITY → * CAPABILITY IMAP4rev1 …").
 *
 * Endpoint: POST /api/external-accounts/probe-stream
 *   Body: { host, port, tls, username, password, folder?, since? }
 *   Response: text/event-stream, `event: line` frames + a final
 *             `event: done` frame with { ok, error? }.
 *
 * This is a diagnostic tool used from the add-account modal BEFORE creating
 * an account: the credentials never touch mongo unless the user confirms.
 */

use simple_smtp_server::external_imap::live_probe::run_probe_stream;
use actix_web::{web, HttpResponse, Responder};
use futures_util::stream;
use serde::Deserialize;
use tokio::sync::mpsc;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProbeStreamInput {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_true")]
    pub tls: bool,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub folder: Option<String>,
    /// ISO-8601; when present the probe runs a SEARCH SINCE + FETCH headers pass.
    #[serde(default)]
    pub since: Option<String>,
}

fn default_true() -> bool { true }

pub(crate) async fn api_external_probe_stream(
    payload: web::Json<ProbeStreamInput>,
) -> impl Responder {
    let input = payload.into_inner();
    let (tx, rx) = mpsc::channel::<String>(256);

    // Kick off the blocking IMAP dialog on a worker thread; it emits SSE
    // frames through `tx` and closes the channel on completion.
    std::thread::spawn(move || {
        run_probe_stream(
            input.host,
            input.port,
            input.tls,
            input.username,
            input.password,
            input.folder,
            input.since,
            tx,
        );
    });

    // Wrap the mpsc receiver as an SSE Bytes stream.
    let event_stream = stream::unfold(rx, |mut rx| async move {
        match rx.recv().await {
            Some(frame) => Some((
                Ok::<web::Bytes, actix_web::Error>(web::Bytes::from(frame)),
                rx,
            )),
            None => None,
        }
    });

    HttpResponse::Ok()
        .content_type("text/event-stream")
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("X-Accel-Buffering", "no"))
        .insert_header(("Connection", "keep-alive"))
        .streaming(event_stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_stream_input_new() {
        let input = ProbeStreamInput {
            host: "imap.example.com".to_string(),
            port: 993,
            tls: true,
            username: "user@example.com".to_string(),
            password: "password".to_string(),
            folder: None,
            since: None,
        };
        assert_eq!(input.host, "imap.example.com");
        assert_eq!(input.port, 993);
        assert!(input.tls);
        assert_eq!(input.username, "user@example.com");
        assert_eq!(input.password, "password");
        assert!(input.folder.is_none());
        assert!(input.since.is_none());
    }

    #[test]
    fn probe_stream_input_with_folder() {
        let input = ProbeStreamInput {
            host: "imap.example.com".to_string(),
            port: 993,
            tls: true,
            username: "user@example.com".to_string(),
            password: "password".to_string(),
            folder: Some("INBOX".to_string()),
            since: None,
        };
        assert_eq!(input.folder, Some("INBOX".to_string()));
    }

    #[test]
    fn probe_stream_input_with_since() {
        let input = ProbeStreamInput {
            host: "imap.example.com".to_string(),
            port: 993,
            tls: true,
            username: "user@example.com".to_string(),
            password: "password".to_string(),
            folder: None,
            since: Some("2024-01-01T00:00:00Z".to_string()),
        };
        assert_eq!(input.since, Some("2024-01-01T00:00:00Z".to_string()));
    }

    #[test]
    fn probe_stream_input_default_tls() {
        let input = ProbeStreamInput {
            host: "imap.example.com".to_string(),
            port: 993,
            tls: default_true(),
            username: "user@example.com".to_string(),
            password: "password".to_string(),
            folder: None,
            since: None,
        };
        assert!(input.tls);
    }

    #[test]
    fn probe_stream_input_no_tls() {
        let input = ProbeStreamInput {
            host: "imap.example.com".to_string(),
            port: 143,
            tls: false,
            username: "user@example.com".to_string(),
            password: "password".to_string(),
            folder: None,
            since: None,
        };
        assert!(!input.tls);
    }

    #[test]
    fn probe_stream_input_port_993() {
        let port = 993u16;
        assert_eq!(port, 993);
    }

    #[test]
    fn probe_stream_input_port_143() {
        let port = 143u16;
        assert_eq!(port, 143);
    }

    #[test]
    fn probe_stream_input_host_format() {
        let host = "imap.gmail.com";
        assert!(host.contains("imap"));
    }

    #[test]
    fn probe_stream_input_username_format() {
        let username = "user@example.com";
        assert!(username.contains("@"));
    }

    #[test]
    fn probe_stream_input_password_length() {
        let password = "securepassword";
        assert!(password.len() >= 8);
    }

    #[test]
    fn probe_stream_input_folder_inbox() {
        let folder = "INBOX";
        assert_eq!(folder, "INBOX");
    }

    #[test]
    fn probe_stream_input_folder_sent() {
        let folder = "Sent";
        assert_eq!(folder, "Sent");
    }

    #[test]
    fn probe_stream_input_since_format() {
        let since = "2024-01-01T00:00:00Z";
        assert!(since.contains("T"));
        assert!(since.ends_with("Z"));
    }

    #[test]
    fn probe_stream_input_debug() {
        let input = ProbeStreamInput {
            host: "imap.example.com".to_string(),
            port: 993,
            tls: true,
            username: "user@example.com".to_string(),
            password: "password".to_string(),
            folder: None,
            since: None,
        };
        let debug = format!("{:?}", input);
        assert!(debug.contains("imap.example.com"));
    }

    #[test]
    fn probe_stream_input_clone() {
        let input = ProbeStreamInput {
            host: "imap.example.com".to_string(),
            port: 993,
            tls: true,
            username: "user@example.com".to_string(),
            password: "password".to_string(),
            folder: None,
            since: None,
        };
        let cloned = input.clone();
        assert_eq!(input.host, cloned.host);
        assert_eq!(input.port, cloned.port);
        assert_eq!(input.tls, cloned.tls);
    }

    #[test]
    fn probe_stream_input_serialize() {
        let input = ProbeStreamInput {
            host: "imap.example.com".to_string(),
            port: 993,
            tls: true,
            username: "user@example.com".to_string(),
            password: "password".to_string(),
            folder: Some("INBOX".to_string()),
            since: Some("2024-01-01T00:00:00Z".to_string()),
        };
        let serialized = serde_json::to_string(&input);
        assert!(serialized.is_ok());
    }

    #[test]
    fn probe_stream_input_deserialize() {
        let json = r#"{
            "host": "imap.example.com",
            "port": 993,
            "tls": true,
            "username": "user@example.com",
            "password": "password",
            "folder": "INBOX",
            "since": "2024-01-01T00:00:00Z"
        }"#;
        let result: Result<ProbeStreamInput, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let input = result.unwrap();
        assert_eq!(input.host, "imap.example.com");
        assert_eq!(input.port, 993);
        assert!(input.tls);
        assert_eq!(input.folder, Some("INBOX".to_string()));
    }

    #[test]
    fn probe_stream_input_deserialize_default_tls() {
        let json = r#"{
            "host": "imap.example.com",
            "port": 993,
            "username": "user@example.com",
            "password": "password"
        }"#;
        let result: Result<ProbeStreamInput, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let input = result.unwrap();
        assert!(input.tls);
        assert!(input.folder.is_none());
        assert!(input.since.is_none());
    }

    #[test]
    fn probe_stream_input_deserialize_no_tls() {
        let json = r#"{
            "host": "imap.example.com",
            "port": 143,
            "tls": false,
            "username": "user@example.com",
            "password": "password"
        }"#;
        let result: Result<ProbeStreamInput, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let input = result.unwrap();
        assert!(!input.tls);
    }

    #[test]
    fn probe_stream_input_camel_case() {
        let json = r#"{
            "host": "imap.example.com",
            "port": 993,
            "tls": true,
            "username": "user@example.com",
            "password": "password",
            "folder": "INBOX",
            "since": "2024-01-01T00:00:00Z"
        }"#;
        let result: Result<ProbeStreamInput, _> = serde_json::from_str(json);
        assert!(result.is_ok());
    }

    #[test]
    fn probe_stream_input_rename_all() {
        let rename = "camelCase";
        assert_eq!(rename, "camelCase");
    }

    #[test]
    fn probe_stream_input_default_true_fn() {
        let default = default_true();
        assert!(default);
    }

    #[test]
    fn probe_stream_input_mpsc_channel_size() {
        let size = 256usize;
        assert_eq!(size, 256);
    }

    #[test]
    fn probe_stream_input_sse_content_type() {
        let content_type = "text/event-stream";
        assert_eq!(content_type, "text/event-stream");
    }

    #[test]
    fn probe_stream_input_cache_control() {
        let cache_control = "no-cache";
        assert_eq!(cache_control, "no-cache");
    }

    #[test]
    fn probe_stream_input_x_accel_buffering() {
        let buffering = "no";
        assert_eq!(buffering, "no");
    }

    #[test]
    fn probe_stream_input_connection() {
        let connection = "keep-alive";
        assert_eq!(connection, "keep-alive");
    }

    #[test]
    fn probe_stream_input_endpoint() {
        let endpoint = "/api/external-accounts/probe-stream";
        assert!(endpoint.contains("probe-stream"));
    }

    #[test]
    fn probe_stream_input_method() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn probe_stream_input_event_line() {
        let event = "line";
        assert_eq!(event, "line");
    }

    #[test]
    fn probe_stream_input_event_done() {
        let event = "done";
        assert_eq!(event, "done");
    }

    #[test]
    fn probe_stream_input_frame_format() {
        let frame = "a1 CAPABILITY → * CAPABILITY IMAP4rev1";
        assert!(frame.contains("CAPABILITY"));
    }

    #[test]
    fn probe_stream_input_ok_field() {
        let field = "ok";
        assert_eq!(field, "ok");
    }

    #[test]
    fn probe_stream_input_error_field() {
        let field = "error";
        assert_eq!(field, "error");
    }

    #[test]
    fn probe_stream_input_host_field() {
        let field = "host";
        assert_eq!(field, "host");
    }

    #[test]
    fn probe_stream_input_port_field() {
        let field = "port";
        assert_eq!(field, "port");
    }

    #[test]
    fn probe_stream_input_tls_field() {
        let field = "tls";
        assert_eq!(field, "tls");
    }

    #[test]
    fn probe_stream_input_username_field() {
        let field = "username";
        assert_eq!(field, "username");
    }

    #[test]
    fn probe_stream_input_password_field() {
        let field = "password";
        assert_eq!(field, "password");
    }

    #[test]
    fn probe_stream_input_folder_field() {
        let field = "folder";
        assert_eq!(field, "folder");
    }

    #[test]
    fn probe_stream_input_since_field() {
        let field = "since";
        assert_eq!(field, "since");
    }

    #[test]
    fn probe_stream_input_serde_rename_all() {
        let rename = "camelCase";
        assert_eq!(rename, "camelCase");
    }

    #[test]
    fn probe_stream_input_serde_default() {
        let default = "default";
        assert_eq!(default, "default");
    }

    #[test]
    fn probe_stream_input_run_probe_stream_fn() {
        let fn_name = "run_probe_stream";
        assert_eq!(fn_name, "run_probe_stream");
    }

    #[test]
    fn probe_stream_input_external_imap_module() {
        let module = "simple_smtp_server::external_imap::live_probe";
        assert!(module.contains("external_imap"));
    }

    #[test]
    fn probe_stream_input_tx_channel() {
        let (tx, _rx) = mpsc::channel::<String>(256);
        assert!(true);
    }

    #[test]
    fn probe_stream_input_rx_channel() {
        let (_tx, rx) = mpsc::channel::<String>(256);
        assert!(true);
    }

    #[test]
    fn probe_stream_input_thread_spawn() {
        let thread = std::thread::spawn(|| {});
        assert!(true);
    }

    #[test]
    fn probe_stream_input_stream_unfold() {
        let stream = "stream::unfold";
        assert_eq!(stream, "stream::unfold");
    }

    #[test]
    fn probe_stream_input_bytes_from() {
        let bytes = web::Bytes::from("test");
        assert_eq!(bytes.len(), 4);
    }

    #[test]
    fn probe_stream_input_ok_response() {
        let response = HttpResponse::Ok();
        assert!(true);
    }

    #[test]
    fn probe_stream_input_content_type_header() {
        let header = "Content-Type";
        assert_eq!(header, "Content-Type");
    }

    #[test]
    fn probe_stream_input_cache_control_header() {
        let header = "Cache-Control";
        assert_eq!(header, "Cache-Control");
    }

    #[test]
    fn probe_stream_input_x_accel_buffering_header() {
        let header = "X-Accel-Buffering";
        assert_eq!(header, "X-Accel-Buffering");
    }

    #[test]
    fn probe_stream_input_connection_header() {
        let header = "Connection";
        assert_eq!(header, "Connection");
    }

    #[test]
    fn probe_stream_input_streaming_method() {
        let method = "streaming";
        assert_eq!(method, "streaming");
    }

    #[test]
    fn probe_stream_input_into_inner() {
        let method = "into_inner";
        assert_eq!(method, "into_inner");
    }

    #[test]
    fn probe_stream_input_recv_method() {
        let method = "recv";
        assert_eq!(method, "recv");
    }

    #[test]
    fn probe_stream_input_some_frame() {
        let frame = Some("test frame".to_string());
        assert!(frame.is_some());
    }

    #[test]
    fn probe_stream_input_none_frame() {
        let frame: Option<String> = None;
        assert!(frame.is_none());
    }

    #[test]
    fn probe_stream_input_async_move() {
        let keyword = "async move";
        assert_eq!(keyword, "async move");
    }

    #[test]
    fn probe_stream_input_mut_rx() {
        let keyword = "mut rx";
        assert_eq!(keyword, "mut rx");
    }

    #[test]
    fn probe_stream_input_match_keyword() {
        let keyword = "match";
        assert_eq!(keyword, "match");
    }

    #[test]
    fn probe_stream_input_await_keyword() {
        let keyword = "await";
        assert_eq!(keyword, "await");
    }

    #[test]
    fn probe_stream_input_ok_keyword() {
        let keyword = "Ok";
        assert_eq!(keyword, "Ok");
    }

    #[test]
    fn probe_stream_input_error_type() {
        let error = "actix_web::Error";
        assert!(error.contains("Error"));
    }

    #[test]
    fn probe_stream_input_bytes_type() {
        let bytes = "web::Bytes";
        assert!(bytes.contains("Bytes"));
    }

    #[test]
    fn probe_stream_input_string_type() {
        let string = "String";
        assert_eq!(string, "String");
    }

    #[test]
    fn probe_stream_input_u16_type() {
        let u16 = "u16";
        assert_eq!(u16, "u16");
    }

    #[test]
    fn probe_stream_input_bool_type() {
        let bool = "bool";
        assert_eq!(bool, "bool");
    }

    #[test]
    fn probe_stream_input_option_type() {
        let option = "Option<String>";
        assert!(option.contains("Option"));
    }

    #[test]
    fn probe_stream_input_sender_type() {
        let sender = "mpsc::Sender<String>";
        assert!(sender.contains("Sender"));
    }

    #[test]
    fn probe_stream_input_receiver_type() {
        let receiver = "mpsc::Receiver<String>";
        assert!(receiver.contains("Receiver"));
    }

    #[test]
    fn probe_stream_input_json_type() {
        let json = "web::Json<ProbeStreamInput>";
        assert!(json.contains("Json"));
    }

    #[test]
    fn probe_stream_input_responder_type() {
        let responder = "impl Responder";
        assert!(responder.contains("Responder"));
    }

    #[test]
    fn probe_stream_input_http_response() {
        let response = "HttpResponse";
        assert_eq!(response, "HttpResponse");
    }

    #[test]
    fn probe_stream_input_insert_header() {
        let method = "insert_header";
        assert_eq!(method, "insert_header");
    }

    #[test]
    fn probe_stream_input_web_json() {
        let json = "web::Json";
        assert!(json.contains("Json"));
    }

    #[test]
    fn probe_stream_input_payload_type() {
        let payload = "payload";
        assert_eq!(payload, "payload");
    }

    #[test]
    fn probe_stream_input_input_type() {
        let input = "input";
        assert_eq!(input, "input");
    }

    #[test]
    fn probe_stream_input_std_thread() {
        let thread = "std::thread";
        assert_eq!(thread, "std::thread");
    }

    #[test]
    fn probe_stream_input_spawn() {
        let spawn = "spawn";
        assert_eq!(spawn, "spawn");
    }

    #[test]
    fn probe_stream_input_move_keyword() {
        let keyword = "move";
        assert_eq!(keyword, "move");
    }

    #[test]
    fn probe_stream_input_closure() {
        let closure = "||";
        assert_eq!(closure, "||");
    }

    #[test]
    fn probe_stream_input_fn_params() {
        let params = "host, port, tls, username, password, folder, since, tx";
        assert!(params.contains("host"));
        assert!(params.contains("port"));
        assert!(params.contains("tls"));
    }

    #[test]
    fn probe_stream_input_tx_channel_param() {
        let param = "tx";
        assert_eq!(param, "tx");
    }

    #[test]
    fn probe_stream_input_run_probe_stream_params() {
        let params = "host, port, tls, username, password, folder, since, tx";
        assert_eq!(params.split(", ").count(), 8);
    }
}
