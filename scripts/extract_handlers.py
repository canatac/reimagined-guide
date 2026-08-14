#!/usr/bin/env python3
"""
Sprint 5: Extract handlers from main.rs into sub-modules
- event_handlers.rs : persist_event, emit_event, api_events, api_events_stream
- mailing_list_handlers.rs : create_mailing_list, send_to_mailing_list, normalize_*
- send_handlers.rs : send_email_handler, welcome_email_html, req_ip_str, get_accept_language
"""
import subprocess, re, os

main_path = "/root/reimagined-guide/src/bin/email_api_dir/main.rs"
lines = open(main_path).readlines()
content = "".join(lines)

# Find line boundaries (0-indexed)
def find_fn(name, lines):
    for i, l in enumerate(lines):
        if f"fn {name}" in l or f"async fn {name}" in l:
            return i
    return None

# Find function block end by brace counting
def fn_end(start, lines):
    depth = 0
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth <= 0 and i > start:
            return i + 1
    return len(lines)

# Identify blocks
blocks = {}
for name in ["persist_event", "emit_event", "api_events", "api_events_stream",
             "normalize_segment", "build_misfits_local", "normalize_oauth_provider",
             "create_mailing_list", "send_to_mailing_list",
             "send_email_handler", "req_ip_str", "get_accept_language",
             "welcome_email_html"]:
    start = find_fn(name, lines)
    if start is not None:
        end = fn_end(start, lines)
        blocks[name] = (start, end)
        print(f"{name}: L{start+1}-{end}")

# Group into modules
event_fns = ["persist_event", "emit_event", "api_events", "api_events_stream"]
mailing_fns = ["normalize_segment", "build_misfits_local", "normalize_oauth_provider",
               "create_mailing_list", "send_to_mailing_list"]
send_fns = ["send_email_handler", "req_ip_str", "get_accept_language", "welcome_email_html"]

# Collect standard use statements from main.rs for each module
common_uses = """use actix_web::{web, HttpRequest, HttpResponse, Responder};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use std::env;
use simple_smtp_server::entities::MailEvent;
"""

base_path = "/root/reimagined-guide/src/bin/email_api_dir"

for module_name, fn_names in [
    ("event_handlers2", event_fns),
    ("mailing_list_handlers2", mailing_fns),
    ("send_handlers", send_fns),
]:
    fn_blocks = []
    for name in fn_names:
        if name in blocks:
            s, e = blocks[name]
            fn_blocks.append("".join(lines[s:e]))

    if not fn_blocks:
        print(f"No functions for {module_name}")
        continue

    module_content = f"// {module_name}.rs — extracted Sprint 5\n#![allow(dead_code, unused_imports)]\n\n{common_uses}\n\n"
    module_content += "\n\n".join(fn_blocks)
    path = f"{base_path}/{module_name}.rs"
    open(path, "w").write(module_content)
    print(f"Created {module_name}.rs: {len(module_content.splitlines())} lines")

print("Done — next step: remove functions from main.rs and add mod declarations")
