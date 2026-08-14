#!/usr/bin/env python3
"""Fix Sprint 9:
1. Make extracted fns pub(crate) so pub use *::* actually re-exports them
2. Add missing crate:: imports for monitoring/security in extracted modules
"""
import re, os

extract_files = [
    "/root/reimagined-guide/src/bin/email_api_dir/event_handlers.rs",
    "/root/reimagined-guide/src/bin/email_api_dir/oauth_utils.rs",
    "/root/reimagined-guide/src/bin/email_api_dir/mailing_list_handlers.rs",
    "/root/reimagined-guide/src/bin/email_api_dir/send_dispatch.rs",
    "/root/reimagined-guide/src/bin/email_api_dir/web_utils.rs",
]

for p in extract_files:
    c = open(p).read()
    # Make each `async fn X(` and `fn X(` at line-start pub(crate)
    c = re.sub(r'^(async fn )', r'pub(crate) \1', c, flags=re.MULTILINE)
    c = re.sub(r'^(fn )', r'pub(crate) \1', c, flags=re.MULTILINE)
    # Ensure crate:: usable
    if "use crate::" not in c:
        c = c.replace(
            "use super::*;\n",
            "use super::*;\nuse crate::{monitoring, security, admin_ops, monitoring_handlers};\n"
        )
    open(p, "w").write(c)
    print(f"fixed {os.path.basename(p)}")
