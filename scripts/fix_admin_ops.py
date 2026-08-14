#!/usr/bin/env python3
path = "/root/reimagined-guide/src/bin/email_api_dir/admin_ops_handlers.rs"
lines = open(path).readlines()

# Find the last well-formed closing brace before the orphan comment
# The file should end at the last "}" at depth 0
depth = 0
last_zero = 0
for i, line in enumerate(lines):
    s = line.split("//")[0]
    depth += s.count("{") - s.count("}")
    if depth == 0:
        last_zero = i

print(f"Last depth-0 line: {last_zero + 1} (total: {len(lines)})")
# Truncate to last_zero + 1
new_lines = lines[:last_zero + 1]
open(path, "w").writelines(new_lines)
print(f"Truncated to {len(new_lines)} lines")
