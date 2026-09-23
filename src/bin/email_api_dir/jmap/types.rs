//! JMAP protocol types — RFC 8620 (JMAP Core) and RFC 8621 (JMAP Mail).
//!
//! These types model the JMAP request/response format, session resources,
//! and the core JMAP Mail types (Email, Mailbox, EmailSubmission).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ===========================================================================
// JMAP Session Resource (RFC 8620 §2)
// ===========================================================================

/// Full JMAP session resource returned by `GET /jmap/session`.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapSession {
    /// Capabilities the server supports (URIs → extra props).
    pub capabilities: JmapCapabilities,
    /// Per-account map (accountId → Account).
    pub accounts: HashMap<String, JmapAccount>,
    /// Maps capability URIs to their primary accountId.
    pub primary_accounts: HashMap<String, String>,
    /// Username of the authenticated user.
    pub username: String,
    /// URL to the JMAP API endpoint.
    pub api_url: String,
    /// URL template for blob downloads.
    pub download_url: String,
    /// URL template for blob uploads.
    pub upload_url: String,
    /// Optional EventSource URL for push.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_source_url: Option<String>,
    /// Current state token for the session.
    pub state: String,
}

/// A JMAP Account — a collection of data accessible via a set of types.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapAccount {
    /// Human-readable name.
    pub name: String,
    /// Whether this is the primary account for the user.
    #[serde(default)]
    pub is_personal: bool,
    /// Whether this account is read-only.
    #[serde(default)]
    pub is_read_only: bool,
    /// Capability URIs this account supports.
    #[serde(default)]
    pub account_capabilities: HashMap<String, serde_json::Value>,
}

/// JMAP server capabilities (well-known + session).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapCapabilities {
    /// Max upload size in bytes (urn:ietf:params:jmap:core).
    #[serde(rename = "urn:ietf:params:jmap:core")]
    pub core: JmapCoreCapability,
    /// Mail capability (urn:ietf:params:jmap:mail).
    #[serde(rename = "urn:ietf:params:jmap:mail")]
    pub mail: JmapMailCapability,
}

impl JmapCapabilities {
    pub fn new() -> Self {
        Self {
            core: JmapCoreCapability {
                max_size_upload: 25_000_000,
                max_concurrent_upload: 4,
                max_size_request: 50_000_000,
                max_concurrent_requests: 4,
                max_calls_in_request: 16,
                max_objects_in_get: 500,
                max_objects_in_set: 500,
                collation_algorithms: vec!["i;unicode-casemap".to_string()],
            },
            mail: JmapMailCapability {
                max_mailboxes_per_email: Some(1),
                max_mailboxes_per_thread: Some(1),
                max_size_mailbox_query: 1000,
                max_size_thread_query: 1000,
                emails_max_size_attachments: 25_000_000,
            },
        }
    }
}

impl Default for JmapCapabilities {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapCoreCapability {
    pub max_size_upload: u64,
    pub max_concurrent_upload: u64,
    pub max_size_request: u64,
    pub max_concurrent_requests: u64,
    pub max_calls_in_request: u64,
    pub max_objects_in_get: u64,
    pub max_objects_in_set: u64,
    #[serde(default)]
    pub collation_algorithms: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapMailCapability {
    pub max_mailboxes_per_email: Option<u64>,
    pub max_mailboxes_per_thread: Option<u64>,
    pub max_size_mailbox_query: u64,
    pub max_size_thread_query: u64,
    pub emails_max_size_attachments: u64,
}

// ===========================================================================
// JMAP Request / Response (RFC 8620 §3.3)
// ===========================================================================

/// A JMAP request: a list of method calls + the capabilities being used.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapRequest {
    /// Capability URIs the client is using.
    #[serde(default)]
    pub using: Vec<String>,
    /// Ordered list of method calls: [methodName, arguments, callId].
    #[serde(default)]
    pub method_calls: Vec<serde_json::Value>,
    /// If true, created ids are returned as a map (default false).
    #[serde(default)]
    pub created_ids: bool,
}

impl JmapRequest {
    pub fn new() -> Self {
        Self {
            using: vec![
                "urn:ietf:params:jmap:core".to_string(),
                "urn:ietf:params:jmap:mail".to_string(),
            ],
            method_calls: Vec::new(),
            created_ids: false,
        }
    }
}

impl Default for JmapRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// A JMAP response: a list of method responses.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapResponse {
    /// Ordered list of method responses: [methodName, arguments, callId].
    #[serde(default)]
    pub method_responses: Vec<serde_json::Value>,
    /// Map of client-supplied creation id → server-assigned id.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub created_ids: HashMap<String, String>,
    /// Session state token.
    #[serde(default)]
    pub session_state: String,
}

impl JmapResponse {
    pub fn new() -> Self {
        Self {
            method_responses: Vec::new(),
            created_ids: HashMap::new(),
            session_state: "state-0".to_string(),
        }
    }

    pub fn with_state(state: &str) -> Self {
        Self {
            method_responses: Vec::new(),
            created_ids: HashMap::new(),
            session_state: state.to_string(),
        }
    }

    /// Push a method response.
    pub fn push_response(&mut self, name: &str, args: serde_json::Value, call_id: &str) {
        self.method_responses
            .push(serde_json::json!([name, args, call_id]));
    }

    /// Push an error response.
    pub fn push_error(&mut self, error_type: &str, description: &str, call_id: &str) {
        self.method_responses.push(serde_json::json!([
            "error",
            { "type": error_type, "description": description },
            call_id
        ]));
    }
}

impl Default for JmapResponse {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// JMAP Mail Types (RFC 8621)
// ===========================================================================

/// JMAP Email object (RFC 8621 §4).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapEmail {
    /// Email id.
    pub id: String,
    /// Blob id for the raw message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_id: Option<String>,
    /// Thread id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    /// Mailbox ids this email belongs to.
    #[serde(default)]
    pub mailbox_ids: HashMap<String, bool>,
    /// Keywords (flags).
    #[serde(default)]
    pub keywords: HashMap<String, bool>,
    /// Size in bytes.
    #[serde(default)]
    pub size: u64,
    /// Received at (RFC 3339).
    pub received_at: String,
    /// Subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// From addresses.
    #[serde(default)]
    pub from: Vec<JmapAddress>,
    /// To addresses.
    #[serde(default)]
    pub to: Vec<JmapAddress>,
    /// CC addresses.
    #[serde(default)]
    pub cc: Vec<JmapAddress>,
    /// BCC addresses.
    #[serde(default)]
    pub bcc: Vec<JmapAddress>,
    /// Reply-to addresses.
    #[serde(default)]
    pub reply_to: Vec<JmapAddress>,
    /// In-reply-to message id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    /// Message-ID header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    /// Preview text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    /// Text body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_body: Option<String>,
    /// HTML body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html_body: Option<String>,
    /// Has attachment flag.
    #[serde(default)]
    pub has_attachment: bool,
}

/// JMAP Address type.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapAddress {
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Email address.
    pub email: String,
}

/// JMAP Mailbox object (RFC 8621 §2).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapMailbox {
    /// Mailbox id.
    pub id: String,
    /// Name (e.g. "Inbox").
    pub name: String,
    /// Parent mailbox id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// Role (e.g. "inbox", "sent", "trash").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Sort order.
    #[serde(default)]
    pub sort_order: u64,
    /// Total emails.
    #[serde(default)]
    pub total_emails: u64,
    /// Unread emails.
    #[serde(default)]
    pub unread_emails: u64,
    /// Total threads.
    #[serde(default)]
    pub total_threads: u64,
    /// Unread threads.
    #[serde(default)]
    pub unread_threads: u64,
    /// My rights.
    #[serde(default)]
    pub my_rights: JmapMailboxRights,
}

/// Mailbox rights (RFC 8621 §2.3).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapMailboxRights {
    /// May see the mailbox in LIST.
    #[serde(default = "default_true")]
    pub may_read_items: bool,
    /// May add/remove messages.
    #[serde(default = "default_true")]
    pub may_add_items: bool,
    /// May modify keywords.
    #[serde(default = "default_true")]
    pub may_remove_items: bool,
    /// May create child mailboxes.
    #[serde(default = "default_true")]
    pub may_create_child: bool,
    /// May rename the mailbox.
    #[serde(default = "default_true")]
    pub may_rename: bool,
    /// May delete the mailbox.
    #[serde(default = "default_true")]
    pub may_delete: bool,
    /// May set seen flag.
    #[serde(default = "default_true")]
    pub may_set_seen: bool,
    /// May set keywords.
    #[serde(default = "default_true")]
    pub may_set_keywords: bool,
}

fn default_true() -> bool {
    true
}

impl Default for JmapMailboxRights {
    fn default() -> Self {
        Self {
            may_read_items: true,
            may_add_items: true,
            may_remove_items: true,
            may_create_child: true,
            may_rename: true,
            may_delete: true,
            may_set_seen: true,
            may_set_keywords: true,
        }
    }
}

// ===========================================================================
// JMAP Method Arguments
// ===========================================================================

/// Arguments for `Email/get` (RFC 8621 §4.3).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapEmailGetArgs {
    /// Account id.
    #[serde(default)]
    pub account_id: String,
    /// Email ids (null = all).
    #[serde(default)]
    pub ids: Option<Vec<String>>,
    /// Properties to return.
    #[serde(default)]
    pub properties: Option<Vec<String>>,
    /// Body properties to return.
    #[serde(default = "default_body_properties")]
    pub body_properties: Vec<String>,
    /// Fetch text body values.
    #[serde(default)]
    pub fetch_text_body_values: bool,
    /// Fetch HTML body values.
    #[serde(default)]
    pub fetch_html_body_values: bool,
    /// Fetch all body values.
    #[serde(default)]
    pub fetch_all_body_values: bool,
    /// Max body value bytes.
    #[serde(default)]
    pub max_body_value_bytes: Option<u64>,
}

fn default_body_properties() -> Vec<String> {
    vec![
        "mailboxIds".to_string(),
        "keywords".to_string(),
        "size".to_string(),
        "receivedAt".to_string(),
        "subject".to_string(),
        "from".to_string(),
        "to".to_string(),
        "messageId".to_string(),
    ]
}

impl Default for JmapEmailGetArgs {
    fn default() -> Self {
        Self {
            account_id: String::new(),
            ids: None,
            properties: None,
            body_properties: default_body_properties(),
            fetch_text_body_values: false,
            fetch_html_body_values: false,
            fetch_all_body_values: false,
            max_body_value_bytes: None,
        }
    }
}

/// Arguments for `Email/query` (RFC 8621 §4.4).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapEmailQueryArgs {
    /// Account id.
    #[serde(default)]
    pub account_id: String,
    /// Filter condition.
    #[serde(default)]
    pub filter: Option<serde_json::Value>,
    /// Sort comparators.
    #[serde(default)]
    pub sort: Option<Vec<serde_json::Value>>,
    /// Position in result set.
    #[serde(default)]
    pub position: i64,
    /// Anchor email id.
    #[serde(default)]
    pub anchor: Option<String>,
    /// Anchor offset.
    #[serde(default)]
    pub anchor_offset: i64,
    /// Max results.
    #[serde(default = "default_query_limit")]
    pub limit: Option<u64>,
    /// Calculate total count.
    #[serde(default)]
    pub calculate_total: bool,
}

fn default_query_limit() -> Option<u64> {
    Some(10)
}

impl Default for JmapEmailQueryArgs {
    fn default() -> Self {
        Self {
            account_id: String::new(),
            filter: None,
            sort: None,
            position: 0,
            anchor: None,
            anchor_offset: 0,
            limit: default_query_limit(),
            calculate_total: false,
        }
    }
}

/// Arguments for `Email/set` (RFC 8621 §4.6).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapEmailSetArgs {
    /// Account id.
    #[serde(default)]
    pub account_id: String,
    /// If true, destroy on not found.
    #[serde(default)]
    pub if_in_state: Option<String>,
    /// Create operations.
    #[serde(default)]
    pub create: Option<HashMap<String, serde_json::Value>>,
    /// Update operations.
    #[serde(default)]
    pub update: Option<HashMap<String, serde_json::Value>>,
    /// Destroy ids.
    #[serde(default)]
    pub destroy: Option<Vec<String>>,
}

/// Arguments for `Mailbox/get` (RFC 8621 §2.4).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapMailboxGetArgs {
    /// Account id.
    #[serde(default)]
    pub account_id: String,
    /// Mailbox ids (null = all).
    #[serde(default)]
    pub ids: Option<Vec<String>>,
    /// Properties to return.
    #[serde(default)]
    pub properties: Option<Vec<String>>,
}

impl Default for JmapMailboxGetArgs {
    fn default() -> Self {
        Self {
            account_id: String::new(),
            ids: None,
            properties: None,
        }
    }
}

/// Arguments for `Mailbox/set` (RFC 8621 §2.5).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapMailboxSet {
    /// Account id.
    #[serde(default)]
    pub account_id: String,
    /// If in state.
    #[serde(default)]
    pub if_in_state: Option<String>,
    /// Create operations: client id → Mailbox object.
    #[serde(default)]
    pub create: Option<HashMap<String, JmapMailbox>>,
    /// Update operations: mailbox id → patch object.
    #[serde(default)]
    pub update: Option<HashMap<String, serde_json::Value>>,
    /// Destroy ids.
    #[serde(default)]
    pub destroy: Option<Vec<String>>,
    /// On destroy remove emails.
    #[serde(default = "default_true")]
    pub on_destroy_remove_emails: bool,
}

impl Default for JmapMailboxSet {
    fn default() -> Self {
        Self {
            account_id: String::new(),
            if_in_state: None,
            create: None,
            update: None,
            destroy: None,
            on_destroy_remove_emails: true,
        }
    }
}

/// Arguments for `EmailSubmission/get` (RFC 8621 §7.3).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapEmailSubmissionGetArgs {
    #[serde(default)]
    pub account_id: String,
    #[serde(default)]
    pub ids: Option<Vec<String>>,
    #[serde(default)]
    pub properties: Option<Vec<String>>,
}

/// Arguments for `EmailSubmission/set` (RFC 8621 §7.4).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapEmailSubmissionSet {
    #[serde(default)]
    pub account_id: String,
    #[serde(default)]
    pub if_in_state: Option<String>,
    #[serde(default)]
    pub create: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub update: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub destroy: Option<Vec<String>>,
}

/// Arguments for `Email/queryChanges` (RFC 8620 §5.4).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapEmailQueryChangesArgs {
    #[serde(default)]
    pub account_id: String,
    #[serde(default)]
    pub filter: Option<serde_json::Value>,
    #[serde(default)]
    pub sort: Option<Vec<serde_json::Value>>,
    /// Since state.
    pub since_query_state: String,
    #[serde(default = "default_max_changes")]
    pub max_changes: u64,
    #[serde(default)]
    pub up_to_id: Option<String>,
    #[serde(default = "default_true")]
    pub calculate_total: bool,
}

fn default_max_changes() -> u64 {
    100
}

// ===========================================================================
// JMAP Error Types
// ===========================================================================

/// JMAP error object.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JmapError {
    /// Error type URI.
    #[serde(rename = "type")]
    pub error_type: String,
    /// HTTP status code.
    #[serde(default)]
    pub status: u16,
    /// Detailed description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl JmapError {
    pub fn account_not_found() -> Self {
        Self {
            error_type: "accountNotFound".to_string(),
            status: 404,
            detail: Some("Account not found".to_string()),
        }
    }

    pub fn invalid_arguments(detail: &str) -> Self {
        Self {
            error_type: "invalidArguments".to_string(),
            status: 400,
            detail: Some(detail.to_string()),
        }
    }

    pub fn server_fail(detail: &str) -> Self {
        Self {
            error_type: "serverFail".to_string(),
            status: 500,
            detail: Some(detail.to_string()),
        }
    }

    pub fn cannot_calculate_changes() -> Self {
        Self {
            error_type: "cannotCalculateChanges".to_string(),
            status: 409,
            detail: Some("State has changed, please resync".to_string()),
        }
    }

    pub fn unknown_method(name: &str) -> Self {
        Self {
            error_type: "unknownMethod".to_string(),
            status: 400,
            detail: Some(format!("Unknown method: {name}")),
        }
    }

    pub fn not_found(detail: &str) -> Self {
        Self {
            error_type: "notFound".to_string(),
            status: 404,
            detail: Some(detail.to_string()),
        }
    }

    pub fn state_mismatch() -> Self {
        Self {
            error_type: "stateMismatch".to_string(),
            status: 409,
            detail: Some("Client state does not match server state".to_string()),
        }
    }
}

// ===========================================================================
// JMAP EmailSubmission Type
// ===========================================================================

/// JMAP EmailSubmission object (RFC 8621 §7).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapEmailSubmission {
    /// Submission id.
    pub id: String,
    /// Identity id.
    pub identity_id: String,
    /// Email id being sent.
    pub email_id: String,
    /// Envelope (from, to).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<JmapEnvelope>,
    /// Send at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_at: Option<String>,
    /// Undo status.
    #[serde(default = "default_undo_status")]
    pub undo_status: String,
    /// Delivery status.
    #[serde(default)]
    pub delivery_status: HashMap<String, String>,
    /// Dsn blob ids.
    #[serde(default)]
    pub dsn_blob_ids: Vec<String>,
    /// Blob ids.
    #[serde(default)]
    pub blob_ids: Vec<String>,
}

fn default_undo_status() -> String {
    "final".to_string()
}

/// JMAP Envelope.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapEnvelope {
    /// Mail from.
    pub mail_from: JmapEnvelopeAddress,
    /// RCPT TO.
    pub rcpt_to: Vec<JmapEnvelopeAddress>,
}

/// JMAP Envelope Address.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapEnvelopeAddress {
    /// Email address.
    pub email: String,
    /// Parameter.
    #[serde(default)]
    pub parameter: Option<serde_json::Value>,
}

// ===========================================================================
// JMAP Identity Type
// ===========================================================================

/// JMAP Identity object (RFC 8621 §8).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapIdentity {
    /// Identity id.
    pub id: String,
    /// Name.
    #[serde(default)]
    pub name: String,
    /// Email.
    pub email: String,
    /// Reply-to.
    #[serde(default)]
    pub reply_to: Option<Vec<JmapAddress>>,
    /// Bcc.
    #[serde(default)]
    pub bcc: Option<Vec<JmapAddress>>,
    /// Text signature.
    #[serde(default)]
    pub text_signature: String,
    /// HTML signature.
    #[serde(default)]
    pub html_signature: String,
    /// May delete.
    #[serde(default = "default_true")]
    pub may_delete: bool,
}

// ===========================================================================
// JMAP Thread Type
// ===========================================================================

/// JMAP Thread object (RFC 8621 §3).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapThread {
    /// Thread id.
    pub id: String,
    /// Email ids.
    #[serde(default)]
    pub email_ids: Vec<String>,
}

// ===========================================================================
// JMAP VacationResponse Type
// ===========================================================================

/// JMAP VacationResponse object (RFC 8621 §9).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapVacationResponse {
    /// Id.
    pub id: String,
    /// Is enabled.
    #[serde(default)]
    pub is_enabled: bool,
    /// From date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_date: Option<String>,
    /// To date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_date: Option<String>,
    /// Subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Text body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_body: Option<String>,
    /// HTML body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html_body: Option<String>,
}

// ===========================================================================
// JMAP SearchSnippet Type
// ===========================================================================

/// JMAP SearchSnippet (RFC 8621 §4.5).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapSearchSnippet {
    /// Email id.
    pub email_id: String,
    /// Subject snippet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Preview snippet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
}

// ===========================================================================
// JMAP PushSubscription Type
// ===========================================================================

/// JMAP PushSubscription (RFC 8620 §7.3).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapPushSubscription {
    /// Id.
    pub id: String,
    /// Device client id.
    pub device_client_id: String,
    /// URL.
    pub url: String,
    /// Keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<JmapPushKeys>,
    /// Verification code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_code: Option<String>,
    /// Expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Types.
    #[serde(default)]
    pub types: Vec<String>,
}

/// JMAP Push keys.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JmapPushKeys {
    pub p256dh: String,
    pub auth: String,
}

// ===========================================================================
// JMAP Blob Type
// ===========================================================================

/// JMAP Blob reference.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JmapBlob {
    /// Id.
    pub id: String,
    /// Type.
    #[serde(rename = "type")]
    pub blob_type: String,
    /// Size.
    pub size: u64,
    /// Name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

// ===========================================================================
// JMAP UTILITY: Convert internal Email to JMAP Email
// ===========================================================================

impl JmapEmail {
    /// Convert an internal `simple_smtp_server::entities::Email` to a JMAP Email.
    pub fn from_internal_email(email: &simple_smtp_server::entities::Email) -> Self {
        let mailbox_ids: HashMap<String, bool> = [("inbox".to_string(), true)].into_iter().collect();
        let keywords: HashMap<String, bool> = email
            .flags
            .iter()
            .map(|f| (f.clone(), true))
            .collect();

        Self {
            id: email.id.clone(),
            blob_id: Some(format!("blob-{}", email.id)),
            thread_id: Some(format!("thread-{}", email.id)),
            mailbox_ids,
            keywords,
            size: email.body.len() as u64 + email.subject.len() as u64,
            received_at: email.internal_date.to_rfc3339(),
            subject: if email.subject.is_empty() {
                None
            } else {
                Some(email.subject.clone())
            },
            from: vec![JmapAddress {
                name: None,
                email: email.from.clone(),
            }],
            to: vec![JmapAddress {
                name: None,
                email: email.to.clone(),
            }],
            cc: Vec::new(),
            bcc: Vec::new(),
            reply_to: Vec::new(),
            in_reply_to: None,
            message_id: Some(format!("<{}@jmap.local>", email.id)),
            preview: {
                let preview: String = email.body.chars().take(200).collect();
                if preview.is_empty() {
                    None
                } else {
                    Some(preview)
                }
            },
            text_body: Some(email.body.clone()),
            html_body: None,
            has_attachment: false,
        }
    }
}

impl JmapMailbox {
    /// Create a JMAP Mailbox from a name and role.
    pub fn from_name(name: &str, role: Option<&str>, id: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            parent_id: None,
            role: role.map(|s| s.to_string()),
            sort_order: 0,
            total_emails: 0,
            unread_emails: 0,
            total_threads: 0,
            unread_threads: 0,
            my_rights: JmapMailboxRights::default(),
        }
    }
}
