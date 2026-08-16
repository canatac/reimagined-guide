// Split into domain-focused test submodules (cycle 23) to keep < 300 LOC.
#[path = "tests_dir/users.rs"] mod users;
#[path = "tests_dir/emails.rs"] mod emails;
#[path = "tests_dir/mailbox.rs"] mod mailbox;
#[path = "tests_dir/store.rs"] mod store;
