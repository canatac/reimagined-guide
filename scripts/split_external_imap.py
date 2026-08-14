#!/usr/bin/env python3
"""Sprint 14: split external_imap/mod.rs (1303 LOC) impl ExternalImapService by domain."""
import re, os

src = "/root/reimagined-guide/src/external_imap/mod.rs"
lines = open(src).readlines()
n = len(lines)

impl_start = None
for i, l in enumerate(lines):
    if l.startswith("impl ExternalImapService {"):
        impl_start = i
        break
assert impl_start is not None
print(f"impl starts L{impl_start+1}")

# Find impl end: line "}" at column 0 that closes the last method
# The impl continues to end of file? Check
# There may be helper impls at end. We'll assume impl spans until the last method's closing brace.
# Actually the whole file may be one impl. Let's find the LAST bare "}" in the file that isn't part of a nested block.
# Simpler: find each pub/async fn boundary by looking at column-4 "    pub" or "    fn" or "    async"

def find_fn_line(pattern):
    """Find first line starting with `    pub? async? fn NAME` matching pattern."""
    for i, l in enumerate(lines):
        m = re.match(r'^    (?:pub )?(?:async )?fn ([a-zA-Z_][a-zA-Z0-9_]*)', l)
        if m and m.group(1) == pattern:
            return i
    return -1

def back_to_blank(i):
    while i > 0 and lines[i-1].strip() == "":
        i -= 1
    return i

# Cut points based on grep output (0-indexed line numbers)
cut_account = back_to_blank(find_fn_line("create_account"))       # ~156
cut_folder = back_to_blank(find_fn_line("list_folders"))          # ~284
cut_sync = back_to_blank(find_fn_line("start_sync_run"))          # ~376
cut_message = back_to_blank(find_fn_line("list_messages"))        # ~472
cut_imap = back_to_blank(find_fn_line("imap_test"))               # ~579

# Find impl closing: assume it's the "}" at column 0 AFTER the last impl method (before helper impls or end of file)
# Find first "}" line >= imap section end. Since imap_test extends to the end, find "}" at col 0 near L1066 (from grep).
# Actually L1066 is the closing of impl. Let's verify.
impl_end = None
# From the grep: 1066, 1160, 1172, 1226, 1234, 1247, 1263, 1303 all "}"
# L1066 = end of impl ExternalImapService
# Rest = helper impls (Display, From, etc.)
impl_end = 1065  # 0-indexed

print(f"cut points: account={cut_account+1} folder={cut_folder+1} sync={cut_sync+1} message={cut_message+1} imap={cut_imap+1} impl_end={impl_end+1}")

def wrap(name, body):
    return (
        f"// {name}.rs — split from external_imap/mod.rs (Sprint 14)\n"
        "#![allow(unused_imports)]\n"
        "use super::*;\n\n"
        "impl ExternalImapService {\n"
        + body
        + "}\n"
    )

out_dir = "/root/reimagined-guide/src/external_imap"

parts = [
    ("account_ops.rs", cut_account, cut_folder),
    ("folder_ops.rs", cut_folder, cut_sync),
    ("sync_ops.rs", cut_sync, cut_message),
    ("message_ops.rs", cut_message, cut_imap),
    ("imap_client_ops.rs", cut_imap, impl_end),
]

for name, s, e in parts:
    body = "".join(lines[s:e])
    open(os.path.join(out_dir, name), "w").write(wrap(name, body))
    print(f"  {name}: {e-s} lines")

# Rewrite mod.rs:
# keep [:cut_account] (structs + impl start + new/db_name/coll_*)
# + close impl: "}\n"
# + mod declarations
# + [impl_end+1:] (helpers Display/etc.)
mod_decls = "\nmod account_ops;\nmod folder_ops;\nmod sync_ops;\nmod message_ops;\nmod imap_client_ops;\n\n"
new = lines[:cut_account] + ["}\n"] + [mod_decls] + lines[impl_end+1:]
open(src, "w").writelines(new)
print(f"mod.rs: {len(new)} lines (was {n})")
