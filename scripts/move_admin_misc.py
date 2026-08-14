#!/usr/bin/env python3
"""
move_admin_misc.py — Sprint 2
Déplace les handlers admin divers (security_posture, deliverability, observability)
de main.rs vers admin_ops_handlers.rs.
"""
path = "/root/reimagined-guide/src/bin/email_api_dir/main.rs"
admin_path = "/root/reimagined-guide/src/bin/email_api_dir/admin_ops_handlers.rs"

lines = open(path).readlines()

# Find boundaries: api_admin_security_posture at line 350 (index 349)
# ends at normalize_segment start (line 1134, index 1133)
# We need to find normalize_segment exactly

start_idx = None
end_idx = None
for i, line in enumerate(lines):
    if "async fn api_admin_security_posture" in line and start_idx is None:
        # include the DeliverabilityDiagnosticsQuery type a few lines before
        # Find the struct DeliverabilityDiagnosticsQuery
        for j in range(max(0, i-30), i):
            if "struct DeliverabilityDiagnosticsQuery" in lines[j] or "struct AdminWindowQuery" in lines[j]:
                start_idx = j
                break
        if start_idx is None:
            start_idx = i
    if "fn normalize_segment" in line and start_idx is not None and end_idx is None:
        end_idx = i  # exclusive

if start_idx is None or end_idx is None:
    print(f"ERROR: start={start_idx}, end={end_idx}")
    exit(1)

print(f"Extracting lines {start_idx+1}-{end_idx} from main.rs → admin_ops_handlers.rs")

extracted = lines[start_idx:end_idx]

# Also remove dns_txt_lookup from main.rs if it's used only by these handlers
# Find it
dns_start = None
dns_end = None
for i, line in enumerate(lines):
    if "async fn dns_txt_lookup" in line:
        dns_start = i
    if dns_start is not None and dns_end is None and i > dns_start + 2 and line.strip() == "}":
        dns_end = i + 1
        break

# Append extracted to admin_ops_handlers.rs
with open(admin_path, "a") as f:
    f.write("\n// ─── Admin misc (security_posture, deliverability, observability) ──────────\n\n")
    if dns_start is not None:
        f.writelines(lines[dns_start:dns_end])
        f.write("\n")
    f.writelines(extracted)

# Remove from main.rs
dns_remove_start = dns_start if dns_start is not None else start_idx
dns_remove_end = dns_end if dns_end is not None else start_idx

# Remove in reverse order if dns block is before extracted
new_lines = lines[:dns_remove_start] + lines[dns_remove_end:start_idx] + lines[end_idx:]
with open(path, "w") as f:
    f.writelines(new_lines)

print(f"Done. main.rs: {len(new_lines)} lines, admin_ops_handlers.rs: {sum(1 for _ in open(admin_path))} lines")
