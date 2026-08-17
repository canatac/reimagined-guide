// User-related trait method delegations.
async fn insert_user(&self, user: User) -> Result<()> {
    self.insert_user_impl(user).await
}
async fn find_user(&self, username: &str, password: &str) -> Result<Option<User>> {
    self.find_user_impl(username, password).await
}
async fn create_user(&self, username: &str, password: &str, mailbox: &str) -> Result<()> {
    self.create_user_impl(username, password, mailbox).await
}
async fn authenticate_user(&self, username: &str, password: &str) -> Result<Option<User>> {
    self.authenticate_user_impl(username, password).await
}
async fn update_user_locale(&self, username: &str, locale: &str) -> Result<()> {
    self.update_user_locale_impl(username, locale).await
}
async fn find_or_create_oauth_user(
    &self,
    provider: &str,
    provider_user_id: &str,
    email: &str,
    display_name: Option<&str>,
) -> Result<User> {
    self.find_or_create_oauth_user_impl(provider, provider_user_id, email, display_name).await
}
async fn create_alias(&self, alias: &str, target: &str) -> Result<()> {
    self.create_alias_impl(alias, target).await
}
