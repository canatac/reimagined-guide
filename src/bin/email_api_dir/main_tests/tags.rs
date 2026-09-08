use super::super::super::*;

#[test]
fn test_mail_label_create_request_deserializes_camel_case_fields() {
    let parsed: MailLabelCreateRequest = serde_json::from_value(serde_json::json!({
        "name": "Finance",
        "color": "#22c55e",
        "icon": "banknote",
        "parentId": "root-label"
    }))
    .expect("MailLabelCreateRequest should deserialize");

    assert_eq!(parsed.name, "Finance");
    assert_eq!(parsed.color.as_deref(), Some("#22c55e"));
    assert_eq!(parsed.icon.as_deref(), Some("banknote"));
    assert_eq!(parsed.parent_id.as_deref(), Some("root-label"));
}

#[test]
fn test_mail_label_update_request_deserializes_partial_payload() {
    let parsed: MailLabelUpdateRequest = serde_json::from_value(serde_json::json!({
        "name": "Urgent",
        "parentId": ""
    }))
    .expect("MailLabelUpdateRequest should deserialize");

    assert_eq!(parsed.name.as_deref(), Some("Urgent"));
    assert_eq!(parsed.parent_id.as_deref(), Some(""));
    assert!(parsed.color.is_none());
    assert!(parsed.icon.is_none());
}
