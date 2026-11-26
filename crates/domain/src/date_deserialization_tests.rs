//! Tests for BSON Date and RFC 3339 date deserialization
//! 
//! These tests verify that the custom deserializers handle both:
//! - BSON Date format: {"$date": "2026-01-01T12:00:00Z"}
//! - RFC 3339 format: "2026-01-01T12:00:00Z"
//! 
//! Coverage for issue #769 acceptance criteria:
//! - AC1: A date field stored as BSON Date deserializes without the 'invalid type: map' error
//! - AC2: A date field stored as an RFC 3339 string still deserializes
//! - AC3: A deserialization test covers both forms

use chrono::{DateTime, Utc};

#[test]
fn test_deserialize_datetime_utc_from_rfc3339_string() {
    // AC2: RFC 3339 string deserialization
    let json_str = r#""2026-01-01T12:00:00Z""#;
    let result: Result<DateTime<Utc>, _> = serde_json::from_str(json_str);
    assert!(result.is_ok(), "Failed to deserialize RFC3339 string: {:?}", result);
    let dt = result.unwrap();
    assert_eq!(dt.year(), 2026);
    assert_eq!(dt.month(), 1);
    assert_eq!(dt.day(), 1);
    assert_eq!(dt.hour(), 12);
}

#[test]
fn test_deserialize_datetime_utc_from_bson_date() {
    // AC1: BSON Date deserialization without 'invalid type: map' error
    let json_str = r#"{"$date": "2026-01-01T12:00:00Z"}"#;
    let result: Result<DateTime<Utc>, _> = serde_json::from_str(json_str);
    assert!(result.is_ok(), "Failed to deserialize BSON Date: {:?}", result);
    let dt = result.unwrap();
    assert_eq!(dt.year(), 2026);
}

#[test]
fn test_deserialize_option_datetime_utc_none() {
    let json_str = "null";
    let result: Result<Option<DateTime<Utc>>, _> = serde_json::from_str(json_str);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[test]
fn test_deserialize_option_datetime_utc_from_rfc3339() {
    // AC2: RFC 3339 string for Option
    let json_str = r#""2026-01-01T12:00:00Z""#;
    let result: Result<Option<DateTime<Utc>>, _> = serde_json::from_str(json_str);
    assert!(result.is_ok());
    let dt = result.unwrap().unwrap();
    assert_eq!(dt.year(), 2026);
}

#[test]
fn test_deserialize_option_datetime_utc_from_bson_date() {
    // AC1: BSON Date for Option
    let json_str = r#"{"$date": "2026-01-01T12:00:00Z"}"#;
    let result: Result<Option<DateTime<Utc>>, _> = serde_json::from_str(json_str);
    assert!(result.is_ok(), "Failed to deserialize BSON Date for Option: {:?}", result);
    let dt = result.unwrap().unwrap();
    assert_eq!(dt.year(), 2026);
}

#[test]
fn test_external_imap_account_deserialization_with_bson_dates() {
    // AC1 & AC2: ExternalImapAccount with BSON Date format
    let json_str = r#"{"id":"account-1","ownerUserId":"user-1","provider":"gmail","email":"test@gmail.com","authType":"oauth2","imapHost":"imap.gmail.com","imapPort":993,"imapTls":true,"status":"active","createdAt":{"$date":"2026-01-01T12:00:00Z"},"updatedAt":{"$date":"2026-01-02T12:00:00Z"},"lastSyncAt":{"$date":"2026-01-03T12:00:00Z"},"oauthTokenExpiresAt":{"$date":"2026-01-04T12:00:00Z"}}"#;
    let result: Result<super::ExternalImapAccount, _> = serde_json::from_str(json_str);
    assert!(result.is_ok(), "Failed to deserialize ExternalImapAccount with BSON dates: {:?}", result);
    let account = result.unwrap();
    assert_eq!(account.id, "account-1");
    assert_eq!(account.created_at.year(), 2026);
    assert_eq!(account.updated_at.year(), 2026);
    assert_eq!(account.last_sync_at.unwrap().year(), 2026);
    assert_eq!(account.oauth_token_expires_at.unwrap().year(), 2026);
}

#[test]
fn test_external_imap_account_deserialization_with_rfc3339_dates() {
    // AC2: ExternalImapAccount with RFC 3339 format
    let json_str = r#"{"id":"account-1","ownerUserId":"user-1","provider":"gmail","email":"test@gmail.com","authType":"oauth2","imapHost":"imap.gmail.com","imapPort":993,"imapTls":true,"status":"active","createdAt":"2026-01-01T12:00:00Z","updatedAt":"2026-01-02T12:00:00Z","lastSyncAt":"2026-01-03T12:00:00Z","oauthTokenExpiresAt":"2026-01-04T12:00:00Z"}"#;
    let result: Result<super::ExternalImapAccount, _> = serde_json::from_str(json_str);
    assert!(result.is_ok(), "Failed to deserialize ExternalImapAccount with RFC3339 dates: {:?}", result);
    let account = result.unwrap();
    assert_eq!(account.id, "account-1");
    assert_eq!(account.created_at.year(), 2026);
    assert_eq!(account.updated_at.year(), 2026);
}

#[test]
fn test_external_sync_run_deserialization_with_bson_dates() {
    // AC1 & AC2: ExternalSyncRun with BSON Date format
    let json_str = r#"{"id":"run-1","accountId":"account-1","ownerUserId":"user-1","mode":"incremental","folders":[],"status":"running","statsFetched":0,"statsUpdated":0,"statsDeleted":0,"startedAt":{"$date":"2026-01-01T12:00:00Z"},"endedAt":{"$date":"2026-01-01T13:00:00Z"},"since":{"$date":"2026-01-01T11:00:00Z"}}"#;
    let result: Result<super::ExternalSyncRun, _> = serde_json::from_str(json_str);
    assert!(result.is_ok(), "Failed to deserialize ExternalSyncRun with BSON dates: {:?}", result);
    let run = result.unwrap();
    assert_eq!(run.id, "run-1");
    assert_eq!(run.started_at.year(), 2026);
    assert_eq!(run.ended_at.unwrap().year(), 2026);
    assert_eq!(run.since.unwrap().year(), 2026);
}

#[test]
fn test_external_imap_message_deserialization_with_bson_dates() {
    // AC1 & AC2: ExternalImapMessage with BSON Date format
    let json_str = r#"{"id":"msg-1","accountId":"account-1","folderId":"folder-1","ownerUserId":"user-1","remoteUid":123,"messageIdHeader":"<msg1@example.com>","threadKey":"thread-1","from":"sender@example.com","to":"recipient@example.com","subject":"Test","sentAt":{"$date":"2026-01-01T12:00:00Z"},"internalDate":{"$date":"2026-01-01T12:00:00Z"},"flags":[],"bodyPreview":"Preview","rawRef":"ref-1","dedupHash":"hash-1","deleted":false,"createdAt":{"$date":"2026-01-01T12:00:00Z"},"updatedAt":{"$date":"2026-01-01T12:00:00Z"}}"#;
    let result: Result<super::ExternalImapMessage, _> = serde_json::from_str(json_str);
    assert!(result.is_ok(), "Failed to deserialize ExternalImapMessage with BSON dates: {:?}", result);
    let msg = result.unwrap();
    assert_eq!(msg.id, "msg-1");
    assert_eq!(msg.sent_at.unwrap().year(), 2026);
    assert_eq!(msg.internal_date.unwrap().year(), 2026);
}

#[test]
fn test_calendar_event_deserialization_with_bson_dates() {
    // AC1 & AC2: CalendarEvent with BSON Date format
    let json_str = r#"{"id":"event-1","userId":"user-1","title":"Meeting","description":"Test meeting","start":{"$date":"2026-01-01T12:00:00Z"},"end":{"$date":"2026-01-01T13:00:00Z"},"eventType":"default","color":"#3788d8","location":"Office","createdAt":{"$date":"2026-01-01T10:00:00Z"},"updatedAt":{"$date":"2026-01-01T11:00:00Z"}}"#;
    let result: Result<super::CalendarEvent, _> = serde_json::from_str(json_str);
    assert!(result.is_ok(), "Failed to deserialize CalendarEvent with BSON dates: {:?}", result);
    let event = result.unwrap();
    assert_eq!(event.id, "event-1");
    assert_eq!(event.start.year(), 2026);
    assert_eq!(event.end.year(), 2026);
}

#[test]
fn test_email_deserialization_with_bson_date() {
    // AC1 & AC2: Email with BSON Date format
    let json_str = r#"{"id":"email-1","from":"sender@example.com","to":"recipient@example.com","subject":"Test","body":"Body","headers":[],"flags":[],"sequenceNumber":0,"uid":0,"internalDate":{"$date":"2026-01-01T12:00:00Z"},"dkimSignature":null}"#;
    let result: Result<super::Email, _> = serde_json::from_str(json_str);
    assert!(result.is_ok(), "Failed to deserialize Email with BSON date: {:?}", result);
    let email = result.unwrap();
    assert_eq!(email.id, "email-1");
    assert_eq!(email.internal_date.year(), 2026);
}

#[test]
fn test_external_imap_folder_deserialization_with_bson_dates() {
    // AC1 & AC2: ExternalImapFolder with BSON Date format
    let json_str = r#"{"id":"folder-1","accountId":"account-1","ownerUserId":"user-1","remoteName":"INBOX","localRole":"inbox","uidValidity":123,"highestUid":456,"highestModseq":789,"createdAt":{"$date":"2026-01-01T12:00:00Z"},"updatedAt":{"$date":"2026-01-02T12:00:00Z"}}"#;
    let result: Result<super::ExternalImapFolder, _> = serde_json::from_str(json_str);
    assert!(result.is_ok(), "Failed to deserialize ExternalImapFolder with BSON dates: {:?}", result);
    let folder = result.unwrap();
    assert_eq!(folder.id, "folder-1");
    assert_eq!(folder.created_at.year(), 2026);
    assert_eq!(folder.updated_at.year(), 2026);
}
