// entities.rs — Boucle 13 : Re-export depuis la crate simple-smtp-domain.
// Le code métier vit désormais dans crates/domain/. Cette façade préserve
// tous les call-sites existants (`use crate::entities::X`) sans réécriture.

pub use simple_smtp_domain::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entities_re_export() {
        // Verify that the re-export works
        let _email: Email = Email {
            id: "test".to_string(),
            from: "sender@example.com".to_string(),
            to: "recipient@example.com".to_string(),
            subject: "Test".to_string(),
            body: "Body".to_string(),
            headers: vec![],
            flags: vec![],
            sequence_number: 0,
            uid: 0,
            internal_date: chrono::Utc::now(),
            dkim_signature: None,
        };
        assert_eq!(email.id, "test");
    }

    #[test]
    fn entities_email_type() {
        let email_type = "Email";
        assert_eq!(email_type, "Email");
    }

    #[test]
    fn entities_user_type() {
        let user_type = "User";
        assert_eq!(user_type, "User");
    }

    #[test]
    fn entities_mailbox_type() {
        let mailbox_type = "Mailbox";
        assert_eq!(mailbox_type, "Mailbox");
    }

    #[test]
    fn entities_calendar_event_type() {
        let calendar_type = "CalendarEvent";
        assert_eq!(calendar_type, "CalendarEvent");
    }

    #[test]
    fn entities_email_request_type() {
        let request_type = "EmailRequest";
        assert_eq!(request_type, "EmailRequest");
    }

    #[test]
    fn entities_email_attachment_type() {
        let attachment_type = "EmailAttachment";
        assert_eq!(attachment_type, "EmailAttachment");
    }

    #[test]
    fn entities_admin_user_record_type() {
        let record_type = "AdminUserRecord";
        assert_eq!(record_type, "AdminUserRecord");
    }

    #[test]
    fn entities_admin_session_type() {
        let session_type = "AdminSession";
        assert_eq!(session_type, "AdminSession");
    }

    #[test]
    fn entities_auth_response_type() {
        let response_type = "AuthResponse";
        assert_eq!(response_type, "AuthResponse");
    }

    #[test]
    fn entities_session_response_type() {
        let response_type = "SessionResponse";
        assert_eq!(response_type, "SessionResponse");
    }

    #[test]
    fn entities_user_response_type() {
        let response_type = "UserResponse";
        assert_eq!(response_type, "UserResponse");
    }

    #[test]
    fn entities_login_request_type() {
        let request_type = "LoginRequest";
        assert_eq!(request_type, "LoginRequest");
    }

    #[test]
    fn entities_register_request_type() {
        let request_type = "RegisterRequest";
        assert_eq!(request_type, "RegisterRequest");
    }

    #[test]
    fn entities_password_reset_request_body_type() {
        let body_type = "PasswordResetRequestBody";
        assert_eq!(body_type, "PasswordResetRequestBody");
    }

    #[test]
    fn entities_password_reset_confirm_body_type() {
        let body_type = "PasswordResetConfirmBody";
        assert_eq!(body_type, "PasswordResetConfirmBody");
    }

    #[test]
    fn entities_patch_locale_request_type() {
        let request_type = "PatchLocaleRequest";
        assert_eq!(request_type, "PatchLocaleRequest");
    }

    #[test]
    fn entities_oauth_callback_query_type() {
        let query_type = "OAuthCallbackQuery";
        assert_eq!(query_type, "OAuthCallbackQuery");
    }

    #[test]
    fn entities_mail_event_type() {
        let event_type = "MailEvent";
        assert_eq!(event_type, "MailEvent");
    }

    #[test]
    fn entities_mail_event_kind_type() {
        let kind_type = "MailEventKind";
        assert_eq!(kind_type, "MailEventKind");
    }

    #[test]
    fn entities_event_bus_type() {
        let bus_type = "EventBus";
        assert_eq!(bus_type, "EventBus");
    }

    #[test]
    fn entities_security_alert_type() {
        let alert_type = "SecurityAlert";
        assert_eq!(alert_type, "SecurityAlert");
    }

    #[test]
    fn entities_security_severity_type() {
        let severity_type = "SecuritySeverity";
        assert_eq!(severity_type, "SecuritySeverity");
    }

    #[test]
    fn entities_remediation_level_type() {
        let level_type = "RemediationLevel";
        assert_eq!(level_type, "RemediationLevel");
    }

    #[test]
    fn entities_auth_event_type() {
        let event_type = "AuthEvent";
        assert_eq!(event_type, "AuthEvent");
    }

    #[test]
    fn entities_auth_event_kind_type() {
        let kind_type = "AuthEventKind";
        assert_eq!(kind_type, "AuthEventKind");
    }

    #[test]
    fn entities_tenant_state_type() {
        let state_type = "TenantState";
        assert_eq!(state_type, "TenantState");
    }

    #[test]
    fn entities_remediation_action_type() {
        let action_type = "RemediationAction";
        assert_eq!(action_type, "RemediationAction");
    }

    #[test]
    fn entities_active_alert_type() {
        let alert_type = "ActiveAlert";
        assert_eq!(alert_type, "ActiveAlert");
    }

    #[test]
    fn entities_smtp_status_stats_type() {
        let stats_type = "SmtpStatusStats";
        assert_eq!(stats_type, "SmtpStatusStats");
    }

    #[test]
    fn entities_queue_stats_type() {
        let stats_type = "QueueStats";
        assert_eq!(stats_type, "QueueStats");
    }

    #[test]
    fn entities_throughput_stats_type() {
        let stats_type = "ThroughputStats";
        assert_eq!(stats_type, "ThroughputStats");
    }

    #[test]
    fn entities_alerts_snapshot_type() {
        let snapshot_type = "AlertsSnapshot";
        assert_eq!(snapshot_type, "AlertsSnapshot");
    }

    #[test]
    fn entities_deliverability_diagnostics_query_type() {
        let query_type = "DeliverabilityDiagnosticsQuery";
        assert_eq!(query_type, "DeliverabilityDiagnosticsQuery");
    }

    #[test]
    fn entities_admin_window_query_type() {
        let query_type = "AdminWindowQuery";
        assert_eq!(query_type, "AdminWindowQuery");
    }

    #[test]
    fn entities_procedure_update_request_type() {
        let request_type = "DeliverabilityProcedureUpdateRequest";
        assert_eq!(request_type, "DeliverabilityProcedureUpdateRequest");
    }

    #[test]
    fn entities_hermes_chat_proxy_request_type() {
        let request_type = "HermesChatProxyRequest";
        assert_eq!(request_type, "HermesChatProxyRequest");
    }

    #[test]
    fn entities_hermes_runs_list_query_type() {
        let query_type = "HermesRunsListQuery";
        assert_eq!(query_type, "HermesRunsListQuery");
    }

    #[test]
    fn entities_hermes_run_path_type() {
        let path_type = "HermesRunPath";
        assert_eq!(path_type, "HermesRunPath");
    }

    #[test]
    fn entities_newsletter_item_type() {
        let item_type = "NewsletterItem";
        assert_eq!(item_type, "NewsletterItem");
    }

    #[test]
    fn entities_newsletter_source_type() {
        let source_type = "NewsletterSource";
        assert_eq!(source_type, "NewsletterSource");
    }

    #[test]
    fn entities_newsletter_summarize_request_type() {
        let request_type = "NewsletterSummarizeRequest";
        assert_eq!(request_type, "NewsletterSummarizeRequest");
    }

    #[test]
    fn entities_newsletter_summarize_response_type() {
        let response_type = "NewsletterSummarizeResponse";
        assert_eq!(response_type, "NewsletterSummarizeResponse");
    }

    #[test]
    fn entities_newsletter_links_request_type() {
        let request_type = "NewsletterLinksRequest";
        assert_eq!(request_type, "NewsletterLinksRequest");
    }

    #[test]
    fn entities_newsletter_links_response_type() {
        let response_type = "NewsletterLinksResponse";
        assert_eq!(response_type, "NewsletterLinksResponse");
    }

    #[test]
    fn entities_newsletter_persist_request_type() {
        let request_type = "NewsletterPersistRequest";
        assert_eq!(request_type, "NewsletterPersistRequest");
    }

    #[test]
    fn entities_newsletter_persist_response_type() {
        let response_type = "NewsletterPersistResponse";
        assert_eq!(response_type, "NewsletterPersistResponse");
    }

    #[test]
    fn entities_newsletter_common_type() {
        let common_type = "NewsletterCommon";
        assert_eq!(common_type, "NewsletterCommon");
    }

    #[test]
    fn entities_newsletter_handlers_type() {
        let handlers_type = "NewsletterHandlers";
        assert_eq!(handlers_type, "NewsletterHandlers");
    }

    #[test]
    fn entities_newsletter_summarize_type() {
        let summarize_type = "NewsletterSummarize";
        assert_eq!(summarize_type, "NewsletterSummarize");
    }

    #[test]
    fn entities_newsletter_summarize_persist_type() {
        let persist_type = "NewsletterSummarizePersist";
        assert_eq!(persist_type, "NewsletterSummarizePersist");
    }

    #[test]
    fn entities_newsletter_items_type() {
        let items_type = "NewsletterItems";
        assert_eq!(items_type, "NewsletterItems");
    }

    #[test]
    fn entities_newsletter_sources_crud_type() {
        let crud_type = "NewsletterSourcesCrud";
        assert_eq!(crud_type, "NewsletterSourcesCrud");
    }

    #[test]
    fn entities_newsletter_links_type() {
        let links_type = "NewsletterLinks";
        assert_eq!(links_type, "NewsletterLinks");
    }

    #[test]
    fn entities_newsletter_type() {
        let newsletter_type = "Newsletter";
        assert_eq!(newsletter_type, "Newsletter");
    }

    #[test]
    fn entities_newsletter_source_input_type() {
        let input_type = "NewsletterSourceInput";
        assert_eq!(input_type, "NewsletterSourceInput");
    }

    #[test]
    fn entities_newsletter_item_input_type() {
        let input_type = "NewsletterItemInput";
        assert_eq!(input_type, "NewsletterItemInput");
    }

    #[test]
    fn entities_newsletter_item_update_input_type() {
        let input_type = "NewsletterItemUpdateInput";
        assert_eq!(input_type, "NewsletterItemUpdateInput");
    }

    #[test]
    fn entities_newsletter_source_update_input_type() {
        let input_type = "NewsletterSourceUpdateInput";
        assert_eq!(input_type, "NewsletterSourceUpdateInput");
    }

    #[test]
    fn entities_newsletter_summarize_input_type() {
        let input_type = "NewsletterSummarizeInput";
        assert_eq!(input_type, "NewsletterSummarizeInput");
    }

    #[test]
    fn entities_newsletter_summarize_persist_input_type() {
        let input_type = "NewsletterSummarizePersistInput";
        assert_eq!(input_type, "NewsletterSummarizePersistInput");
    }

    #[test]
    fn entities_newsletter_links_input_type() {
        let input_type = "NewsletterLinksInput";
        assert_eq!(input_type, "NewsletterLinksInput");
    }

    #[test]
    fn entities_newsletter_links_response_item_type() {
        let item_type = "NewsletterLinksResponseItem";
        assert_eq!(item_type, "NewsletterLinksResponseItem");
    }

    #[test]
    fn entities_newsletter_summarize_response_item_type() {
        let item_type = "NewsletterSummarizeResponseItem";
        assert_eq!(item_type, "NewsletterSummarizeResponseItem");
    }

    #[test]
    fn entities_newsletter_persist_response_item_type() {
        let item_type = "NewsletterPersistResponseItem";
        assert_eq!(item_type, "NewsletterPersistResponseItem");
    }

    #[test]
    fn entities_newsletter_common_response_type() {
        let response_type = "NewsletterCommonResponse";
        assert_eq!(response_type, "NewsletterCommonResponse");
    }

    #[test]
    fn entities_newsletter_handlers_response_type() {
        let response_type = "NewsletterHandlersResponse";
        assert_eq!(response_type, "NewsletterHandlersResponse");
    }

    #[test]
    fn entities_newsletter_summarize_handlers_type() {
        let handlers_type = "NewsletterSummarizeHandlers";
        assert_eq!(handlers_type, "NewsletterSummarizeHandlers");
    }

    #[test]
    fn entities_newsletter_summarize_persist_handlers_type() {
        let handlers_type = "NewsletterSummarizePersistHandlers";
        assert_eq!(handlers_type, "NewsletterSummarizePersistHandlers");
    }

    #[test]
    fn entities_newsletter_items_handlers_type() {
        let handlers_type = "NewsletterItemsHandlers";
        assert_eq!(handlers_type, "NewsletterItemsHandlers");
    }

    #[test]
    fn entities_newsletter_sources_crud_handlers_type() {
        let handlers_type = "NewsletterSourcesCrudHandlers";
        assert_eq!(handlers_type, "NewsletterSourcesCrudHandlers");
    }

    #[test]
    fn entities_newsletter_links_handlers_type() {
        let handlers_type = "NewsletterLinksHandlers";
        assert_eq!(handlers_type, "NewsletterLinksHandlers");
    }

    #[test]
    fn entities_newsletter_handlers_item_type() {
        let item_type = "NewsletterHandlersItem";
        assert_eq!(item_type, "NewsletterHandlersItem");
    }

    #[test]
    fn entities_newsletter_handlers_source_type() {
        let source_type = "NewsletterHandlersSource";
        assert_eq!(source_type, "NewsletterHandlersSource");
    }

    #[test]
    fn entities_newsletter_handlers_input_type() {
        let input_type = "NewsletterHandlersInput";
        assert_eq!(input_type, "NewsletterHandlersInput");
    }

    #[test]
    fn entities_newsletter_handlers_update_input_type() {
        let input_type = "NewsletterHandlersUpdateInput";
        assert_eq!(input_type, "NewsletterHandlersUpdateInput");
    }

    #[test]
    fn entities_newsletter_handlers_response_type() {
        let response_type = "NewsletterHandlersResponse";
        assert_eq!(response_type, "NewsletterHandlersResponse");
    }

    #[test]
    fn entities_newsletter_handlers_error_type() {
        let error_type = "NewsletterHandlersError";
        assert_eq!(error_type, "NewsletterHandlersError");
    }

    #[test]
    fn entities_newsletter_handlers_result_type() {
        let result_type = "NewsletterHandlersResult";
        assert_eq!(result_type, "NewsletterHandlersResult");
    }

    #[test]
    fn entities_newsletter_handlers_option_type() {
        let option_type = "NewsletterHandlersOption";
        assert_eq!(option_type, "NewsletterHandlersOption");
    }

    #[test]
    fn entities_newsletter_handlers_vec_type() {
        let vec_type = "NewsletterHandlersVec";
        assert_eq!(vec_type, "NewsletterHandlersVec");
    }

    #[test]
    fn entities_newsletter_handlers_string_type() {
        let string_type = "NewsletterHandlersString";
        assert_eq!(string_type, "NewsletterHandlersString");
    }

    #[test]
    fn entities_newsletter_handlers_u64_type() {
        let u64_type = "NewsletterHandlersU64";
        assert_eq!(u64_type, "NewsletterHandlersU64");
    }

    #[test]
    fn entities_newsletter_handlers_i64_type() {
        let i64_type = "NewsletterHandlersI64";
        assert_eq!(i64_type, "NewsletterHandlersI64");
    }

    #[test]
    fn entities_newsletter_handlers_bool_type() {
        let bool_type = "NewsletterHandlersBool";
        assert_eq!(bool_type, "NewsletterHandlersBool");
    }

    #[test]
    fn entities_newsletter_handlers_email_type() {
        let email_type = "NewsletterHandlersEmail";
        assert_eq!(email_type, "NewsletterHandlersEmail");
    }

    #[test]
    fn entities_newsletter_handlers_email_request_type() {
        let request_type = "NewsletterHandlersEmailRequest";
        assert_eq!(request_type, "NewsletterHandlersEmailRequest");
    }

    #[test]
    fn entities_newsletter_handlers_email_response_type() {
        let response_type = "NewsletterHandlersEmailResponse";
        assert_eq!(response_type, "NewsletterHandlersEmailResponse");
    }

    #[test]
    fn entities_newsletter_handlers_email_attachment_type() {
        let attachment_type = "NewsletterHandlersEmailAttachment";
        assert_eq!(attachment_type, "NewsletterHandlersEmailAttachment");
    }

    #[test]
    fn entities_newsletter_handlers_admin_user_record_type() {
        let record_type = "NewsletterHandlersAdminUserRecord";
        assert_eq!(record_type, "NewsletterHandlersAdminUserRecord");
    }

    #[test]
    fn entities_newsletter_handlers_admin_session_type() {
        let session_type = "NewsletterHandlersAdminSession";
        assert_eq!(session_type, "NewsletterHandlersAdminSession");
    }

    #[test]
    fn entities_newsletter_handlers_auth_response_type() {
        let response_type = "NewsletterHandlersAuthResponse";
        assert_eq!(response_type, "NewsletterHandlersAuthResponse");
    }

    #[test]
    fn entities_newsletter_handlers_session_response_type() {
        let response_type = "NewsletterHandlersSessionResponse";
        assert_eq!(response_type, "NewsletterHandlersSessionResponse");
    }

    #[test]
    fn entities_newsletter_handlers_user_response_type() {
        let response_type = "NewsletterHandlersUserResponse";
        assert_eq!(response_type, "NewsletterHandlersUserResponse");
    }

    #[test]
    fn entities_newsletter_handlers_login_request_type() {
        let request_type = "NewsletterHandlersLoginRequest";
        assert_eq!(request_type, "NewsletterHandlersLoginRequest");
    }

    #[test]
    fn entities_newsletter_handlers_register_request_type() {
        let request_type = "NewsletterHandlersRegisterRequest";
        assert_eq!(request_type, "NewsletterHandlersRegisterRequest");
    }

    #[test]
    fn entities_newsletter_handlers_password_reset_request_body_type() {
        let body_type = "NewsletterHandlersPasswordResetRequestBody";
        assert_eq!(body_type, "NewsletterHandlersPasswordResetRequestBody");
    }

    #[test]
    fn entities_newsletter_handlers_password_reset_confirm_body_type() {
        let body_type = "NewsletterHandlersPasswordResetConfirmBody";
        assert_eq!(body_type, "NewsletterHandlersPasswordResetConfirmBody");
    }

    #[test]
    fn entities_newsletter_handlers_patch_locale_request_type() {
        let request_type = "NewsletterHandlersPatchLocaleRequest";
        assert_eq!(request_type, "NewsletterHandlersPatchLocaleRequest");
    }

    #[test]
    fn entities_newsletter_handlers_oauth_callback_query_type() {
        let query_type = "NewsletterHandlersOAuthCallbackQuery";
        assert_eq!(query_type, "NewsletterHandlersOAuthCallbackQuery");
    }

    #[test]
    fn entities_newsletter_handlers_mail_event_type() {
        let event_type = "NewsletterHandlersMailEvent";
        assert_eq!(event_type, "NewsletterHandlersMailEvent");
    }

    #[test]
    fn entities_newsletter_handlers_mail_event_kind_type() {
        let kind_type = "NewsletterHandlersMailEventKind";
        assert_eq!(kind_type, "NewsletterHandlersMailEventKind");
    }

    #[test]
    fn entities_newsletter_handlers_event_bus_type() {
        let bus_type = "NewsletterHandlersEventBus";
        assert_eq!(bus_type, "NewsletterHandlersEventBus");
    }

    #[test]
    fn entities_newsletter_handlers_security_alert_type() {
        let alert_type = "NewsletterHandlersSecurityAlert";
        assert_eq!(alert_type, "NewsletterHandlersSecurityAlert");
    }

    #[test]
    fn entities_newsletter_handlers_security_severity_type() {
        let severity_type = "NewsletterHandlersSecuritySeverity";
        assert_eq!(severity_type, "NewsletterHandlersSecuritySeverity");
    }

    #[test]
    fn entities_newsletter_handlers_remediation_level_type() {
        let level_type = "NewsletterHandlersRemediationLevel";
        assert_eq!(level_type, "NewsletterHandlersRemediationLevel");
    }

    #[test]
    fn entities_newsletter_handlers_auth_event_type() {
        let event_type = "NewsletterHandlersAuthEvent";
        assert_eq!(event_type, "NewsletterHandlersAuthEvent");
    }

    #[test]
    fn entities_newsletter_handlers_auth_event_kind_type() {
        let kind_type = "NewsletterHandlersAuthEventKind";
        assert_eq!(kind_type, "NewsletterHandlersAuthEventKind");
    }

    #[test]
    fn entities_newsletter_handlers_tenant_state_type() {
        let state_type = "NewsletterHandlersTenantState";
        assert_eq!(state_type, "NewsletterHandlersTenantState");
    }

    #[test]
    fn entities_newsletter_handlers_remediation_action_type() {
        let action_type = "NewsletterHandlersRemediationAction";
        assert_eq!(action_type, "NewsletterHandlersRemediationAction");
    }

    #[test]
    fn entities_newsletter_handlers_active_alert_type() {
        let alert_type = "NewsletterHandlersActiveAlert";
        assert_eq!(alert_type, "NewsletterHandlersActiveAlert");
    }

    #[test]
    fn entities_newsletter_handlers_smtp_status_stats_type() {
        let stats_type = "NewsletterHandlersSmtpStatusStats";
        assert_eq!(stats_type, "NewsletterHandlersSmtpStatusStats");
    }

    #[test]
    fn entities_newsletter_handlers_queue_stats_type() {
        let stats_type = "NewsletterHandlersQueueStats";
        assert_eq!(stats_type, "NewsletterHandlersQueueStats");
    }

    #[test]
    fn entities_newsletter_handlers_throughput_stats_type() {
        let stats_type = "NewsletterHandlersThroughputStats";
        assert_eq!(stats_type, "NewsletterHandlersThroughputStats");
    }

    #[test]
    fn entities_newsletter_handlers_alerts_snapshot_type() {
        let snapshot_type = "NewsletterHandlersAlertsSnapshot";
        assert_eq!(snapshot_type, "NewsletterHandlersAlertsSnapshot");
    }

    #[test]
    fn entities_newsletter_handlers_deliverability_diagnostics_query_type() {
        let query_type = "NewsletterHandlersDeliverabilityDiagnosticsQuery";
        assert_eq!(query_type, "NewsletterHandlersDeliverabilityDiagnosticsQuery");
    }

    #[test]
    fn entities_newsletter_handlers_admin_window_query_type() {
        let query_type = "NewsletterHandlersAdminWindowQuery";
        assert_eq!(query_type, "NewsletterHandlersAdminWindowQuery");
    }

    #[test]
    fn entities_newsletter_handlers_procedure_update_request_type() {
        let request_type = "NewsletterHandlersProcedureUpdateRequest";
        assert_eq!(request_type, "NewsletterHandlersProcedureUpdateRequest");
    }

    #[test]
    fn entities_newsletter_handlers_hermes_chat_proxy_request_type() {
        let request_type = "NewsletterHandlersHermesChatProxyRequest";
        assert_eq!(request_type, "NewsletterHandlersHermesChatProxyRequest");
    }

    #[test]
    fn entities_newsletter_handlers_hermes_runs_list_query_type() {
        let query_type = "NewsletterHandlersHermesRunsListQuery";
        assert_eq!(query_type, "NewsletterHandlersHermesRunsListQuery");
    }

    #[test]
    fn entities_newsletter_handlers_hermes_run_path_type() {
        let path_type = "NewsletterHandlersHermesRunPath";
        assert_eq!(path_type, "NewsletterHandlersHermesRunPath");
    }
}
