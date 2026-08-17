// Mailbox-related trait method delegations.
async fn select_mailbox(&self, mailbox: &str) -> Result<Mailbox> {
    self.select_mailbox_impl(mailbox).await
}
async fn search_messages(&self, _criteria: &str) -> Result<Vec<u32>> {
    self.search_messages_impl(_criteria).await
}
async fn expunge_mailbox(&self) -> Result<Vec<u32>> {
    self.expunge_mailbox_impl().await
}
async fn copy_messages(&self, _sequence_set: &str, _target_mailbox: &str) -> Result<()> {
    self.copy_messages_impl(_sequence_set, _target_mailbox).await
}
async fn store_flags(
    &self,
    _sequence_set: &str,
    _flags: Vec<String>,
    _mode: &str,
) -> Result<()> {
    self.store_flags_impl(_sequence_set, _flags, _mode).await
}
async fn find_mailbox(&self, _name: &str) -> Result<Option<Mailbox>> {
    self.find_mailbox_impl(_name).await
}
async fn update_mailbox(&self, _mailbox: &str, _update: Mailbox) -> Result<()> {
    self.update_mailbox_impl(_mailbox, _update).await
}
async fn create_mailbox(&self, _mailbox: &str) -> Result<()> {
    self.create_mailbox_impl(_mailbox).await
}
async fn delete_mailbox(&self, _mailbox: &str) -> Result<()> {
    self.delete_mailbox_impl(_mailbox).await
}
async fn rename_mailbox(&self, _old_name: &str, _new_name: &str) -> Result<()> {
    self.rename_mailbox_impl(_old_name, _new_name).await
}
async fn subscribe_mailbox(&self, _mailbox: &str) -> Result<()> {
    self.subscribe_mailbox_impl(_mailbox).await
}
async fn unsubscribe_mailbox(&self, _mailbox: &str) -> Result<()> {
    self.unsubscribe_mailbox_impl(_mailbox).await
}
async fn list_subscribed_mailboxes(
    &self,
    _username: &str,
    _reference: &str,
    _pattern: &str,
) -> Result<Vec<String>> {
    self.list_subscribed_mailboxes_impl(_username, _reference, _pattern).await
}
async fn get_mailbox_status_items(
    &self,
    _username: &str,
    _mailbox: &str,
    _items: &str,
) -> Result<String> {
    self.get_mailbox_status_items_impl(_username, _mailbox, _items).await
}
async fn get_mailbox_status(&self, _username: &str, mailbox: &str) -> Result<Mailbox> {
    self.get_mailbox_status_impl(_username, mailbox).await
}
async fn noop(&self) -> Result<()> {
    self.noop_impl().await
}
async fn close_mailbox(&self) -> Result<()> {
    self.close_mailbox_impl().await
}
async fn check_mailbox(&self) -> Result<()> {
    self.check_mailbox_impl().await
}
async fn list_mailboxes(
    &self,
    _username: &str,
    _reference: &str,
    _mailbox: &str,
) -> Result<Vec<String>> {
    self.list_mailboxes_impl(_username, _reference, _mailbox).await
}
async fn create_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()> {
    self.create_mailbox_for_user_impl(username, mailbox).await
}
async fn delete_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()> {
    self.delete_mailbox_for_user_impl(username, mailbox).await
}
async fn rename_mailbox_for_user(
    &self,
    username: &str,
    old_name: &str,
    new_name: &str,
) -> Result<()> {
    self.rename_mailbox_for_user_impl(username, old_name, new_name).await
}
async fn subscribe_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()> {
    self.subscribe_mailbox_for_user_impl(username, mailbox).await
}
async fn unsubscribe_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()> {
    self.unsubscribe_mailbox_for_user_impl(username, mailbox).await
}
async fn select_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<Mailbox> {
    self.select_mailbox_for_user_impl(username, mailbox).await
}
async fn search_messages_for_user(&self, username: &str, criteria: &str) -> Result<Vec<u32>> {
    self.search_messages_for_user_impl(username, criteria).await
}
async fn expunge_mailbox_for_user(&self, username: &str) -> Result<Vec<u32>> {
    self.expunge_mailbox_for_user_impl(username).await
}
async fn copy_messages_for_user(
    &self,
    username: &str,
    sequence_set: &str,
    _target_mailbox: &str,
) -> Result<()> {
    self.copy_messages_for_user_impl(username, sequence_set, _target_mailbox).await
}
async fn store_flags_for_user(
    &self,
    username: &str,
    sequence_set: &str,
    flags: Vec<String>,
    mode: &str,
) -> Result<()> {
    self.store_flags_for_user_impl(username, sequence_set, flags, mode).await
}
async fn list_subscribed_mailboxes_for_user(&self, username: &str) -> Result<Vec<String>> {
    self.list_subscribed_mailboxes_for_user_impl(username).await
}
async fn list_mailboxes_for_user(
    &self,
    username: &str,
    reference: &str,
    mailbox: &str,
) -> Result<Vec<String>> {
    self.list_mailboxes_for_user_impl(username, reference, mailbox).await
}
