#!/usr/bin/env python3
"""Sprint 11: split logic/mod.rs by splitting the impl Logic block into 3 sub-impls.

Strategy: each sub-file has a `use super::*;` header + `impl Logic { ... }` block containing
a subset of the methods. Rust allows multiple impl blocks for the same type in different files.
"""
import re

src = "/root/reimagined-guide/src/logic/mod.rs"
lines = open(src).readlines()
n = len(lines)

# Find impl Logic start/end and impl LogicTrait start
impl_logic_start = None  # line with "impl Logic {"
for i, l in enumerate(lines):
    if l.startswith("impl Logic {"):
        impl_logic_start = i
        break

logic_trait_start = None
for i, l in enumerate(lines):
    if l.startswith("impl LogicTrait for Logic {"):
        logic_trait_start = i
        break

assert impl_logic_start is not None and logic_trait_start is not None

# Find the closing } of impl Logic (line just before impl LogicTrait, walking back for blank/close)
# Actually simpler: impl Logic ends at line where a lone "}" is at column 0, before impl LogicTrait
impl_logic_end = None
for i in range(logic_trait_start - 1, impl_logic_start, -1):
    if lines[i].rstrip() == "}":
        impl_logic_end = i
        break
assert impl_logic_end is not None
print(f"impl Logic: L{impl_logic_start+1}-{impl_logic_end+1} ({impl_logic_end-impl_logic_start} lines)")

# Split points (0-based line indices, based on method-start grep above):
# We take BLANK LINE before target method to keep clean boundaries.
def method_line(name):
    for i, l in enumerate(lines):
        if re.search(rf'^\s+pub (async )?fn {re.escape(name)}\b', l):
            return i
    return -1

# Boundaries:
email_start = method_line("get_emails")           # ~L391
mailbox_start = method_line("select_mailbox")     # ~L615
calendar_start = method_line("create_calendar_event")  # ~L1060

# Back up one line (blank line above) for cleaner cuts
def back_to_blank(i):
    while i > 0 and lines[i-1].strip() == "":
        i -= 1
    return i

email_start = back_to_blank(email_start)
mailbox_start = back_to_blank(mailbox_start)
calendar_start = back_to_blank(calendar_start)

print(f"cut points: email {email_start+1}, mailbox {mailbox_start+1}, calendar {calendar_start+1}")

# The remaining impl Logic in mod.rs: [impl_logic_start .. email_start] + closing "}"
# email_impl gets [email_start .. mailbox_start]
# mailbox_impl gets [mailbox_start .. calendar_start]
# calendar_impl gets [calendar_start .. impl_logic_end]  (impl_logic_end is line with '}')

def wrap_impl(name, body_lines):
    header = (
        f"// {name}.rs — split from logic/mod.rs (Sprint 11)\n"
        f"// Extends impl Logic with a subset of methods.\n"
        "#![allow(unused_imports)]\n"
        "use super::*;\n\n"
        "impl Logic {\n"
    )
    return header + "".join(body_lines) + "}\n"

import os
out_dir = os.path.dirname(src)
open(os.path.join(out_dir, "email_impl.rs"), "w").write(
    wrap_impl("email_impl", lines[email_start:mailbox_start])
)
open(os.path.join(out_dir, "mailbox_impl.rs"), "w").write(
    wrap_impl("mailbox_impl", lines[mailbox_start:calendar_start])
)
open(os.path.join(out_dir, "calendar_impl.rs"), "w").write(
    wrap_impl("calendar_impl", lines[calendar_start:impl_logic_end])
)

# Rewrite mod.rs: keep lines[0:email_start] + "}\n" + lines[impl_logic_end+1:]
new = (
    lines[:email_start]
    + ["}\n\n"]  # close the (now smaller) impl Logic block
    + ["mod email_impl;\n", "mod mailbox_impl;\n", "mod calendar_impl;\n\n"]
    + lines[impl_logic_end+1:]
)
open(src, "w").writelines(new)
print(f"mod.rs: {len(new)} (was {n})")
for f in ["email_impl.rs", "mailbox_impl.rs", "calendar_impl.rs"]:
    print(f"  {f}: {sum(1 for _ in open(os.path.join(out_dir, f)))} lines")
