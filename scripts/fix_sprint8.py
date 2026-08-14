#!/usr/bin/env python3
"""Fix Sprint 8:
1. Make struct fields pub(crate) on ComposeAttachmentInput + ComposeSendRequest
2. Make build_body_with_attachments pub(crate)
"""
import re

p = "/root/reimagined-guide/src/bin/email_api_dir/mailbox/read_handlers.rs"
c = open(p).read()

# 1. Make build_body_with_attachments pub(crate)
c = c.replace("\nfn build_body_with_attachments(", "\npub(crate) fn build_body_with_attachments(")

# 2. Add pub(crate) to all fields of ComposeSendRequest and ComposeAttachmentInput
def make_pub_fields(struct_name: str, src: str) -> str:
    m = re.search(rf'pub\(crate\) struct {struct_name} \{{', src)
    if not m:
        return src
    start = m.end()
    # find matching closing brace
    depth = 1
    i = start
    while i < len(src) and depth > 0:
        if src[i] == "{": depth += 1
        elif src[i] == "}": depth -= 1
        i += 1
    end = i
    inner = src[start:end]
    # For each line "    ident:" (not #[..]) prepend "pub(crate) "
    def line_fix(line: str) -> str:
        stripped = line.lstrip()
        if not stripped: return line
        if stripped.startswith("#") or stripped.startswith("//"): return line
        # match "ident: Type" pattern
        m2 = re.match(r'(\s*)([a-zA-Z_][a-zA-Z0-9_]*):', line)
        if not m2: return line
        if stripped.startswith("pub"): return line
        indent = m2.group(1)
        return f"{indent}pub(crate) {stripped}"
    new_inner = "\n".join(line_fix(l) for l in inner.split("\n"))
    return src[:start] + new_inner + src[end:]

c = make_pub_fields("ComposeSendRequest", c)
c = make_pub_fields("ComposeAttachmentInput", c)

open(p, "w").write(c)
print("Fixed read_handlers.rs")
