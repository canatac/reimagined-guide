#!/usr/bin/env python3
"""
extract_modules.py — Sprint 2
Extrait mailbox_handlers.rs et admin_ops_handlers.rs depuis main.rs,
puis nettoie main.rs des blocs correspondants.
"""
import os

path = "/root/reimagined-guide/src/bin/email_api_dir/main.rs"
dir_ = os.path.dirname(path)

lines = open(path).readlines()
total = len(lines)

# Boundaries (1-indexed line numbers from grep):
# mailbox block:   L1452 → L2767  (0-indexed: 1451 → 2766)
# admin_ops block: L2768 → L5405  (0-indexed: 2767 → 5404)
# main():          L5406 → end    (0-indexed: 5405 → end)

mb_start  = 1451   # index of first mailbox line (EmailAddressDto)
mb_end    = 2766   # index of last mailbox line (end of api_drafts_delete)
adm_start = 2767   # index of first admin line (ADMIN_USERS_COLL const)
adm_end   = 5404   # index of last admin line (line before async fn main)

mailbox_lines = lines[mb_start:mb_end + 1]
admin_lines   = lines[adm_start:adm_end + 1]

header_mailbox = """\
// mailbox_handlers.rs — extracted from email_api_dir/main.rs Sprint 2
// Handlers: api_emails, api_send, api_send_undo, api_send_schedule,
//           api_send_status, api_email_action, api_drafts_*, send_queue_worker
// Types: EmailAddressDto, EmailDto, ComposerRecipient, DraftDto

use super::*;

"""

header_admin = """\
// admin_ops_handlers.rs — extracted from email_api_dir/main.rs Sprint 2
// Handlers: api_admin_users_list, api_admin_user_*, api_admin_whoami,
//           api_admin_audit_log, api_admin_change_requests_*, log_admin_action,
//           api_admin_deliverability_*, api_admin_security_posture,
//           api_admin_observability_overview, ai-activity, change-request workflow

use super::*;

"""

# Write modules
with open(os.path.join(dir_, "mailbox_handlers.rs"), "w") as f:
    f.write(header_mailbox)
    f.writelines(mailbox_lines)

with open(os.path.join(dir_, "admin_ops_handlers.rs"), "w") as f:
    f.write(header_admin)
    f.writelines(admin_lines)

# Rebuild main.rs: keep everything before mailbox block + comment + keep main()
new_main = (
    lines[:mb_start]
    + ["// mailbox + send + drafts → mailbox_handlers module\n",
       "// admin CRUD + change-requests + deliverability → admin_ops_handlers module\n",
       "\n"]
    + lines[adm_end + 1:]  # from main() onward
)

with open(path, "w") as f:
    f.writelines(new_main)

print(f"mailbox_handlers.rs: {len(mailbox_lines)} lines")
print(f"admin_ops_handlers.rs: {len(admin_lines)} lines")
print(f"main.rs: {len(new_main)} lines (was {total})")
