// Email-related trait method delegations.
async fn find_emails(&self, mailbox: &str) -> Result<Vec<Email>> {
    self.find_emails_impl(mailbox).await
}
async fn find_email(&self, email_id: &str) -> Result<Option<Email>> {
    self.find_email_impl(email_id).await
}
async fn update_email_flag(&self, email_id: &str, flag: &str) -> Result<()> {
    self.update_email_flag_impl(email_id, flag).await
}
async fn delete_email(&self, email_id: &str) -> Result<()> {
    self.delete_email_impl(email_id).await
}
async fn archive_email(&self, email_id: &str) -> Result<()> {
    self.archive_email_impl(email_id).await
}
async fn store_email(&self, username: &str, mailbox: &str, email: &Email) -> Result<()> {
    self.store_email_impl(username, mailbox, email).await
}
async fn get_emails_page(
    &self,
    username: &str,
    mailbox: &str,
    limit: i64,
    skip: u64,
) -> Result<Vec<Email>> {
    self.get_emails_page_impl(username, mailbox, limit, skip).await
}
async fn fetch_email(&self, username: &str, email_id: &str) -> Result<Option<Email>> {
    self.fetch_email_impl(username, email_id).await
}
async fn set_email_read(&self, username: &str, email_id: &str, read: bool) -> Result<bool> {
    self.set_email_read_impl(username, email_id, read).await
}
async fn set_email_starred(&self, username: &str, email_id: &str, starred: bool) -> Result<bool> {
    self.set_email_starred_impl(username, email_id, starred).await
}
async fn move_email_to_mailbox(
    &self,
    username: &str,
    email_id: &str,
    target_mailbox: &str,
) -> Result<bool> {
    self.move_email_to_mailbox_impl(username, email_id, target_mailbox).await
}
async fn deliver_to_inbox(&self, username: &str, email: &Email) -> Result<()> {
    self.deliver_to_inbox_impl(username, email).await
}
async fn log_mail_event(
    &self,
    kind: &str,
    user_id: &str,
    email_id: &str,
    subject: &str,
    from: &str,
    to: &str,
) -> Result<()> {
    self.log_mail_event_impl(kind, user_id, email_id, subject, from, to).await
}
