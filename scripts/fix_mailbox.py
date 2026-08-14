#!/usr/bin/env python3
path = "/root/reimagined-guide/src/bin/email_api_dir/mailbox_handlers.rs"
full_prepend = open("/tmp/email_list_query_full.rs").read()
content = open(path).read()
marker = "\nuse super::*;\n"
idx = content.find(marker)
if idx == -1:
    print("ERROR: marker not found")
else:
    new_content = full_prepend + content[idx:]
    open(path, "w").write(new_content)
    print(f"Done. Lines: {new_content.count(chr(10))}")
