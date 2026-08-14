#!/usr/bin/env python3
"""
Sprint 5: Split admin_ops_handlers.rs (2795 LOC) into sub-modules.
Strategy: rename to mod.rs inside admin_ops/ directory.
Sub-modules:
  admin_ops/user_handlers.rs    (L234-1056)
  admin_ops/cr_handlers.rs      (L1057-1453)
  admin_ops/ai_handlers.rs      (L1454-1642)
  admin_ops/hermes_handlers.rs  (L1643-2011)
  admin_ops/diag_handlers.rs    (L2012-end)
  admin_ops/mod.rs              (helpers/types + pub use re-exports)
"""
import os, re

src = "/root/reimagined-guide/src/bin/email_api_dir/admin_ops_handlers.rs"
lines = open(src).readlines()
total = len(lines)
print(f"Total lines: {total}")

# Boundary detection by first pub(crate) fn/async fn at those approximate lines
def find_first_fn_at(min_line, lines):
    """Find first pub(crate) fn at or after min_line (1-indexed)"""
    for i in range(min_line - 1, len(lines)):
        if lines[i].startswith("pub(crate) async fn ") or lines[i].startswith("pub(crate) fn "):
            return i  # 0-indexed
    return len(lines)

# Find boundaries
user_start = find_first_fn_at(234, lines)
cr_start = find_first_fn_at(1057, lines)
ai_start = find_first_fn_at(1454, lines)
hermes_start = find_first_fn_at(1643, lines)
diag_start = find_first_fn_at(2012, lines)

print(f"user: L{user_start+1}, cr: L{cr_start+1}, ai: L{ai_start+1}, hermes: L{hermes_start+1}, diag: L{diag_start+1}")

# Read the common header (imports + types)
header = "".join(lines[:user_start])

# Extract blocks
user_block   = "".join(lines[user_start:cr_start])
cr_block     = "".join(lines[cr_start:ai_start])
ai_block     = "".join(lines[ai_start:hermes_start])
hermes_block = "".join(lines[hermes_start:diag_start])
diag_block   = "".join(lines[diag_start:])

# Create admin_ops/ directory
out_dir = "/root/reimagined-guide/src/bin/email_api_dir/admin_ops"
os.makedirs(out_dir, exist_ok=True)

# Common prefix for each sub-module
prefix = """#![allow(unused_imports, dead_code)]
use super::*;  // inherit all imports from mod.rs

"""

for name, block in [
    ("user_handlers", user_block),
    ("cr_handlers", cr_block),
    ("ai_handlers", ai_block),
    ("hermes_handlers", hermes_block),
    ("diag_handlers", diag_block),
]:
    path = f"{out_dir}/{name}.rs"
    open(path, "w").write(prefix + block)
    print(f"{name}.rs: {len(block.splitlines())} lines → {path}")

# Write mod.rs with the header + mod declarations + pub use re-exports
mod_rs = header + "\n"
mod_rs += "pub mod user_handlers;\n"
mod_rs += "pub mod cr_handlers;\n"
mod_rs += "pub mod ai_handlers;\n"
mod_rs += "pub mod hermes_handlers;\n"
mod_rs += "pub mod diag_handlers;\n\n"
mod_rs += "pub use user_handlers::*;\n"
mod_rs += "pub use cr_handlers::*;\n"
mod_rs += "pub use ai_handlers::*;\n"
mod_rs += "pub use hermes_handlers::*;\n"
mod_rs += "pub use diag_handlers::*;\n"

open(f"{out_dir}/mod.rs", "w").write(mod_rs)
print(f"mod.rs: {len(mod_rs.splitlines())} lines")

# Update main.rs to use admin_ops instead of admin_ops_handlers
main = "/root/reimagined-guide/src/bin/email_api_dir/main.rs"
mc = open(main).read()
mc = mc.replace("mod admin_ops_handlers;", "mod admin_ops;")
mc = mc.replace("use admin_ops_handlers::", "use admin_ops::")
mc = mc.replace("admin_ops_handlers::", "admin_ops::")
open(main, "w").write(mc)
print(f"main.rs updated: mod admin_ops")

# Rename original file (keep as backup)
import shutil
shutil.move(src, src + ".bak")
print(f"Original → {src}.bak")
