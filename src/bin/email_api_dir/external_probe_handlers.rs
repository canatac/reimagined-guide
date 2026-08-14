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

use crate::external_imap::live_probe::run_probe_stream;
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
