#!/usr/bin/env python3
lines = open('/root/reimagined-guide/src/bin/email_api_dir/main.rs').readlines()
depth = 0
for i, line in enumerate(lines, 1):
    stripped = line.split('//')[0]
    opens = stripped.count('{')
    closes = stripped.count('}')
    depth += opens - closes
    if depth < 0:
        print(f"NEGATIVE depth at line {i}: depth={depth}")
        print(f"  {lines[i-1].rstrip()}")
        break
    if i % 200 == 0:
        print(f"L{i}: depth={depth}")
print(f"Final depth: {depth}")
