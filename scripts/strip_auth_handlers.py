#!/usr/bin/env python3
# Supprime les blocs auth handlers de main.rs (redondants avec auth_handlers.rs)
path = "/root/reimagined-guide/src/bin/email_api_dir/main.rs"
lines = open(path).readlines()
total = len(lines)
print(f"Before: {total} lines")

# Lines are 1-indexed in grep output, 0-indexed in list
# auth_login starts at line 1450 → index 1449
# EmailAddressDto starts at line 2369 → index 2368
# We want to keep line 1449 (the blank before) and replace lines 1450-2368 with a comment

keep_before = lines[:1449]  # up to and including blank line before auth_login
comment = ["// auth_login..api_password_reset_confirm → auth_handlers module\n", "\n"]
keep_after = lines[2368:]   # from EmailAddressDto onward

new_lines = keep_before + comment + keep_after
open(path, "w").writelines(new_lines)
print(f"After: {len(new_lines)} lines (removed {total - len(new_lines)} lines)")
