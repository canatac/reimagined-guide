#!/usr/bin/env python3
"""Add pub to struct fields in ai_handlers.rs"""
import re

ai = "/root/reimagined-guide/src/bin/email_api_dir/admin_ops/ai_handlers.rs"
content = open(ai).read()

# Replace field patterns inside struct blocks
# Pattern: lines with indentation + word + colon (field definition), not already pub
# More robust: just add pub to all non-pub field lines inside structs
lines = content.split("\n")
in_struct = False
depth = 0
result = []
for line in lines:
    stripped = line.strip()
    
    # Detect struct start
    if re.match(r'(#\[derive|pub\(crate\)\s+)?struct\s+\w+', stripped) or \
       re.match(r'pub struct\s+\w+', stripped):
        in_struct = True
        depth = 0
    
    if in_struct:
        depth += line.count("{") - line.count("}")
        if depth <= 0 and in_struct and any(c == "}" for c in line):
            in_struct = False
    
    # Add pub to field lines (inside struct, depth > 0)
    if in_struct and depth > 0:
        # Field line: leading whitespace, then identifier, then colon
        m = re.match(r'^(\s+)(\w[\w\d_]*)(\s*:.+)', line)
        if m and not stripped.startswith("//") and not stripped.startswith("#") \
           and not stripped.startswith("pub") and not stripped.startswith("}") \
           and not stripped.startswith("{"):
            line = m.group(1) + "pub " + m.group(2) + m.group(3)
    
    result.append(line)

new_content = "\n".join(result)

# Verify the specific structs
assert "pub messages:" in new_content or "pub(crate) messages:" in new_content or \
    "    pub messages:" in new_content, "Failed to add pub to messages"

open(ai, "w").write(new_content)
print(f"Done: {len(new_content.splitlines())} lines")

# Show the struct blocks
for i, l in enumerate(new_content.split("\n")[135:185], 136):
    print(f"{i}: {l}")
