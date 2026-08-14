#!/usr/bin/env python3
import sys, os
base = "/root/reimagined-guide/src/bin/email_api_dir"
for f in ["auth_handlers", "monitoring_handlers", "mailbox_handlers", "admin_ops_handlers", "main"]:
    path = os.path.join(base, f"{f}.rs")
    lines = open(path).readlines()
    d = 0
    neg_line = None
    for i, line in enumerate(lines, 1):
        s = line.split("//")[0]
        d += s.count("{") - s.count("}")
        if d < 0 and neg_line is None:
            neg_line = i
    status = f"OK (depth={d})" if d == 0 else f"BAD final={d}"
    neg = f" first_neg=L{neg_line}" if neg_line else ""
    print(f"{f}.rs: {status}{neg}")
