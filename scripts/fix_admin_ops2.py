#!/usr/bin/env python3
# fix_admin_ops2.py — remove duplicates + add missing admin misc handlers

# 1. Remove api_openapi/api_external* duplicates from admin_ops_handlers.rs
path = "/root/reimagined-guide/src/bin/email_api_dir/admin_ops_handlers.rs"
lines = open(path).readlines()
cut_at = None
for i, l in enumerate(lines):
    if 'pub(crate) async fn api_openapi_json' in l:
        cut_at = i
        break
if cut_at:
    open(path, "w").writelines(lines[:cut_at])
    print(f"admin_ops_handlers.rs: cut at {cut_at+1}, kept {cut_at} lines")
else:
    print("api_openapi_json not found in admin_ops_handlers.rs")

# 2. Append admin_misc handlers
misc = open("/tmp/admin_misc.rs").read()
with open(path, "a") as f:
    f.write("\n// ─── Admin misc (security_posture, deliverability, observability) ───\n\n")
    f.write(misc)
print(f"admin_ops_handlers.rs final: {open(path).read().count(chr(10))} lines")
