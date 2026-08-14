#!/usr/bin/env python3
"""Sprint 9: split main.rs (1549 LOC) — extract 5 helper modules keeping main() + routes.

Ranges (0-based, based on grep):
  L212-338 : persist_event/emit_event/api_events/api_events_stream → event_handlers
  L339-396 : normalize_segment/build_misfits_local/normalize_oauth_provider → oauth_utils
  L398-510 : create_mailing_list/send_to_mailing_list → mailing_list_handlers
  L512-586 : send_email_handler → send_dispatch
  L588-663 : req_ip_str/get_accept_language/welcome_email_html → web_utils

Strategy: since main.rs is a binary and its helpers use many local items,
we keep the extracted files as sibling modules of main.rs and declare them via `mod X;` inside main.rs.
"""
import os, re

src = "/root/reimagined-guide/src/bin/email_api_dir/main.rs"
lines = open(src).readlines()
n = len(lines)
print(f"source: {n} lines")

# Find precise ranges by scanning function starts (0-based indices)
def find(pat, from_idx=0):
    for i in range(from_idx, len(lines)):
        if re.match(pat, lines[i]):
            return i
    return -1

def next_top_boundary(from_idx):
    """Return the next line index where a top-level item starts (fn, struct, impl, etc.)"""
    for i in range(from_idx, len(lines)):
        s = lines[i]
        if re.match(r'^(async fn |fn |pub async fn |pub fn |pub struct |struct |impl |pub trait |trait |pub enum |enum |#\[|///|// )', s):
            return i
    return len(lines)

extracts = [
    ("event_handlers", find(r'^async fn persist_event')),
    ("oauth_utils",    find(r'^fn normalize_segment')),
    ("mailing_list_handlers", find(r'^async fn create_mailing_list')),
    ("send_dispatch",  find(r'^async fn send_email_handler')),
    ("web_utils",      find(r'^fn req_ip_str')),
]
# End of last extract is start of main()
main_start = find(r'^async fn main')

# Compute contiguous slices ending where the NEXT extract starts (or main_start)
slices = []
for i, (name, start) in enumerate(extracts):
    end = extracts[i+1][1] if i+1 < len(extracts) else main_start
    slices.append((name, start, end))
    print(f"{name}: L{start+1}-{end}  ({end-start} lines)")

# Write extract files as sibling modules to main.rs
out_dir = os.path.dirname(src)
for name, s, e in slices:
    body = "".join(lines[s:e])
    content = (
        f"// {name}.rs — split from main.rs (Sprint 9)\n"
        "#![allow(unused_imports)]\n"
        "use super::*;\n\n"
        + body
    )
    open(os.path.join(out_dir, f"{name}.rs"), "w").write(content)
    print(f"wrote {name}.rs")

# Rewrite main.rs: keep L0..L211 (imports+types), skip L212..main_start, keep main() onward
first_extract_start = extracts[0][1]
new_main = (
    lines[:first_extract_start]
    + [f"\nmod {name};\n" for name, _, _ in slices]
    + [f"pub use {name}::*;\n" for name, _, _ in slices]
    + ["\n"]
    + lines[main_start:]
)
open(src, "w").writelines(new_main)
print(f"main.rs: {len(new_main)} lines (was {n})")
