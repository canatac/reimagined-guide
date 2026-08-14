#!/usr/bin/env python3
"""Sprint 8: split mailbox_handlers.rs (1912 LOC) into mailbox/ module.

Strategy: rename file to mailbox/mod.rs (keeping helpers/setup), extract
handler groups to sub-files. Since Rust modules within the same crate can
freely use pub(crate) items from siblings, we just need each sub-file to
`use super::*` to reach the helpers in mod.rs.

Ranges (1-based from grep):
  L1-514    : setup + helpers + types      → keep in mod.rs
  L515-863  : read_handlers                → read_handlers.rs
              (api_email_attachment_download, api_emails, api_tags)
  L864-1651 : send_handlers                → send_handlers.rs
              (api_send, api_send_undo, api_send_schedule,
               send_queue_worker, api_send_status)
  L1652-1758: single_handlers              → single_handlers.rs
              (api_email_by_id, api_email_action)
  L1759-end : drafts_handlers              → drafts_handlers.rs
              (api_drafts_list, api_drafts_upsert, api_drafts_delete)
"""
import os
import shutil

src = "/root/reimagined-guide/src/bin/email_api_dir/mailbox_handlers.rs"
out_dir = "/root/reimagined-guide/src/bin/email_api_dir/mailbox"
os.makedirs(out_dir, exist_ok=True)

lines = open(src).readlines()
n = len(lines)
print(f"source: {n} lines")

# Ranges (0-based)
splits = [
    ("mod.rs",             (0, 514)),
    ("read_handlers.rs",   (514, 863)),
    ("send_handlers.rs",   (863, 1651)),
    ("single_handlers.rs", (1651, 1758)),
    ("drafts_handlers.rs", (1758, n)),
]

header_common = "// Sprint 8: split from mailbox_handlers.rs\n#![allow(unused_imports)]\nuse super::*;\n\n"

for fname, (s, e) in splits:
    body = "".join(lines[s:e])
    out = os.path.join(out_dir, fname)
    if fname == "mod.rs":
        # Prepend sub-module declarations
        header = (
            "// mailbox/mod.rs — split from mailbox_handlers.rs (Sprint 8)\n"
            "pub mod read_handlers;\n"
            "pub mod send_handlers;\n"
            "pub mod single_handlers;\n"
            "pub mod drafts_handlers;\n\n"
            "pub use read_handlers::*;\n"
            "pub use send_handlers::*;\n"
            "pub use single_handlers::*;\n"
            "pub use drafts_handlers::*;\n\n"
        )
        content = header + body
    else:
        content = header_common + body
    open(out, "w").write(content)
    print(f"{fname}: {len(content.splitlines())} lines")

# Delete original file
os.remove(src)
print("removed original mailbox_handlers.rs")

# Update main.rs: mod mailbox_handlers → mod mailbox
main_p = "/root/reimagined-guide/src/bin/email_api_dir/main.rs"
c = open(main_p).read()
c = c.replace("mod mailbox_handlers;", "mod mailbox;")
c = c.replace("pub use mailbox_handlers::*;", "pub use mailbox::*;")
open(main_p, "w").write(c)
print("main.rs updated")
