# IMAP Trace ID Runbook
# Issue #437: IMAP trace ids in structured logs
#
# Each IMAP command generates a unique trace_id (UUID v4) for cross-service correlation.
# Logs are emitted in JSON format with the following fields:
#   - trace_id: Unique identifier for the command
#   - user: Username (without domain)
#   - domain: Email domain
#   - command: IMAP command name (SELECT, LOGIN, etc.)
#   - session_id: Session identifier
#   - args: Command arguments (if any)

## Log Format

### Command Log
```json
{"trace_id":"<uuid>","user":"<username>","domain":"<domain>","command":"<command>","session_id":"<session_id>","args":[...]}
```

### Completion Log
```json
{"trace_id":"<uuid>","command":"<command>","success":<bool>,"duration_ms":<ms>}
```

## Correlation Queries

### Find all commands for a trace_id
```bash
grep '"trace_id":"<trace_id>"' /var/log/imap_server.log
```

### Find all commands for a user in a time range
```bash
jq 'select(.user == "username" and .ts >= "2026-09-09T00:00:00Z" and .ts < "2026-09-09T23:59:59Z")' /var/log/imap_server.log
```

### Find failed commands
```bash
jq 'select(.success == false)' /var/log/imap_server.log
```

### Find slow commands (>1000ms)
```bash
jq 'select(.duration_ms > 1000)' /var/log/imap_server.log
```

### Find commands by domain
```bash
jq 'select(.domain == "misfits.ai")' /var/log/imap_server.log
```

## Traced Commands

The following IMAP commands are traced with trace_id:
- APPEND, CAPABILITY, NOOP, LOGOUT, NAMESPACE
- LOGIN, LIST, SELECT, EXAMINE
- CREATE, DELETE, RENAME
- SUBSCRIBE, UNSUBSCRIBE, LSUB
- STATUS, CHECK, CLOSE, EXPUNGE
- SEARCH, COPY

## Alert Rules

Consider setting up alerts for:
1. High error rate: `rate(imap_commands_failed[5m]) > 0.1`
2. High latency: `histogram_quantile(0.95, rate(imap_command_duration_bucket[5m])) > 2000`
3. Unusual command volume: `rate(imap_commands_total[5m]) > 100`
