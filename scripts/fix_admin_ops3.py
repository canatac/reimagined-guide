#!/usr/bin/env python3
# fix_admin_ops3.py — replace truncated admin_misc with complete version

path = "/root/reimagined-guide/src/bin/email_api_dir/admin_ops_handlers.rs"
lines = open(path).readlines()

# Find where admin_misc comment starts (just before api_admin_security_posture)
cut_at = None
for i, l in enumerate(lines):
    if "Admin misc (security_posture" in l:
        cut_at = i
        break

if cut_at is None:
    print("ERROR: marker not found")
    exit(1)

misc = open("/tmp/admin_misc_full.rs").read()
with open(path, "w") as f:
    f.writelines(lines[:cut_at])
    f.write("\n// ─── Admin misc (security_posture, deliverability, observability) ───\n\n")
    f.write(misc)
    f.write("\n")

print(f"Done. Lines: {open(path).read().count(chr(10))}")
