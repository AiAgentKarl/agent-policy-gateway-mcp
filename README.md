# Agent Policy Gateway MCP Server

Compliance and guardrails server for AI agents. Gives companies the tools to run AI agents safely and within regulatory boundaries.

## Why This Exists

As AI agents gain autonomy — making purchases, accessing data, sending emails — companies face real compliance risks:

- **GDPR (EU)**: Agents processing personal data must follow strict rules. Violations cost up to 4% of global revenue.
- **EU AI Act (2024)**: High-risk AI systems need human oversight, transparency, and documentation. Non-compliance means fines up to 35M EUR.
- **Internal Policies**: Companies need spend limits, allowed actions, domain restrictions, and audit trails.

This server provides the "boring infrastructure" that makes autonomous agents enterprise-ready.

## Tools

| Tool | Description |
|------|-------------|
| `check_pii(text)` | Scan text for PII (emails, phones, SSNs, credit cards, IBANs). Returns found types and redacted version. |
| `apply_guardrails(action, context)` | Check if an action is allowed by configurable policies (spend limits, domain allowlists, blocked actions). |
| `log_action(agent_id, action, details)` | Append-only audit log entry with timestamp. Stored in `~/.agent-audit-log/`. |
| `get_audit_log(agent_id, limit)` | Retrieve audit log entries for compliance review. |
| `check_compliance(action_type, jurisdiction)` | Check EU AI Act risk level and GDPR requirements for an action type. |
| `emergency_stop(agent_id, reason)` | Kill switch — logs critical event and returns immediate stop signal. |

## Installation

```bash
# Via pip
pip install agent-policy-gateway-mcp

# Via uvx (no install needed)
uvx agent-policy-gateway-mcp
```

## Configuration

Add to your MCP client config:

```json
{
  "mcpServers": {
    "policy-gateway": {
      "command": "uvx",
      "args": ["agent-policy-gateway-mcp"]
    }
  }
}
```

Or with pip install:

```json
{
  "mcpServers": {
    "policy-gateway": {
      "command": "policy-gateway-server"
    }
  }
}
```

## Usage Examples

### PII Detection Before External Calls

```
check_pii("Send invoice to john.doe@company.com, CC 4532-1234-5678-9012")
→ has_pii: true, found: [email, credit_card], redacted version provided
```

### Guardrails for Agent Actions

```
apply_guardrails("make_purchase", {"amount_usd": 500})
→ denied: exceeds $100 spend limit

apply_guardrails("send_email", {})
→ allowed

apply_guardrails("delete_user_data")
→ denied: blocked action
```

### Compliance Check

```
check_compliance("automated_decision", "EU")
→ risk_level: high
→ requirements: human oversight, transparency, documentation, fairness audits
→ gdpr_articles: Art. 22 GDPR
```

### Emergency Stop

```
emergency_stop("agent-007", "Agent attempting unauthorized data export")
→ kill_switch: true, logged to audit trail
```

## Compliance Coverage

### EU AI Act Risk Levels
- **Unacceptable**: Biometric identification (real-time) — blocked
- **High**: Automated decisions, credit scoring, recruitment, customer profiling
- **Limited**: Content moderation, data processing
- **Minimal**: Chatbot interactions

### GDPR Articles Referenced
- Art. 6 — Lawfulness of processing
- Art. 9 — Special categories of data
- Art. 13/14 — Information obligations
- Art. 21 — Right to object
- Art. 22 — Automated decision-making
- Art. 30 — Records of processing
- Art. 35 — Data protection impact assessment

## Audit Log Format

Logs are stored as JSONL files in `~/.agent-audit-log/`:

```json
{"entry_id": "agent-1_1710936000000", "timestamp": "2024-03-20T12:00:00+00:00", "agent_id": "agent-1", "action": "api_call", "details": "Called external pricing API"}
```

## License

MIT
