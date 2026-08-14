#!/usr/bin/env python3
"""Fix Sprint 5 CI errors:
1. admin_ops_handlers reference in monitoring_handlers.rs
2. Private struct fields in ai_handlers.rs (HermesChatProxyRequest, HermesRunsListQuery, etc.)
"""
import re, glob

# 1. Find remaining references to admin_ops_handlers
for path in glob.glob("/root/reimagined-guide/src/**/*.rs", recursive=True):
    c = open(path).read()
    if "admin_ops_handlers" in c:
        new = c.replace("admin_ops_handlers::", "admin_ops::").replace(
            "super::admin_ops_handlers", "super::admin_ops"
        ).replace(
            "crate::admin_ops_handlers", "crate::admin_ops"
        )
        if new != c:
            open(path, "w").write(new)
            print(f"Fixed admin_ops_handlers ref in {path}")

# 2. Make all struct fields pub in ai_handlers.rs
# The structs defined there: HermesChatProxyRequest, HermesRunsListQuery, HermesRunsProxyRequest
ai = "/root/reimagined-guide/src/bin/email_api_dir/admin_ops/ai_handlers.rs"
c = open(ai).read()

# Find struct definitions and make all fields pub
def make_fields_pub(content):
    """Add 'pub ' before field definitions inside struct blocks"""
    lines = content.split("\n")
    in_struct = False
    brace_depth = 0
    result = []
    for line in lines:
        stripped = line.strip()
        # Detect struct start
        if re.match(r'(pub\s+)?struct\s+\w+', stripped):
            in_struct = True
            brace_depth = 0
        if in_struct:
            brace_depth += line.count("{") - line.count("}")
            if brace_depth <= 0 and "{" in line:
                in_struct = False
            elif in_struct and brace_depth > 0:
                # Field line: "  field_name: Type,"
                m = re.match(r'^(\s+)(\w+)(\s*:.+)', line)
                if m and not stripped.startswith("//") and not stripped.startswith("pub "):
                    line = m.group(1) + "pub " + m.group(2) + m.group(3)
        result.append(line)
    return "\n".join(result)

c = make_fields_pub(c)
open(ai, "w").write(c)
print(f"ai_handlers.rs: fields made pub ({len(c.splitlines())} lines)")

# Same for hermes_handlers.rs if it has structs
hermes = "/root/reimagined-guide/src/bin/email_api_dir/admin_ops/hermes_handlers.rs"
c = open(hermes).read()
c = make_fields_pub(c)
open(hermes, "w").write(c)
print(f"hermes_handlers.rs: fields made pub ({len(c.splitlines())} lines)")
