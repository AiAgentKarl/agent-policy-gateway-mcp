"""
Agent Policy Gateway MCP Server

Compliance-Gateway für AI-Agents: PII-Erkennung, Guardrails,
Audit-Logging, DSGVO/AI-Act-Checks und Notfall-Stopp.

Gibt Unternehmen die Werkzeuge, um AI-Agents sicher und
regelkonform zu betreiben.
"""

from mcp.server.fastmcp import FastMCP

# Server erstellen
mcp = FastMCP(
    "Agent Policy Gateway",
    instructions=(
        "Compliance & guardrails server for AI agents. "
        "Provides PII detection and redaction, configurable action guardrails, "
        "append-only audit logging, GDPR/EU AI Act compliance checks, "
        "and emergency kill-switch capabilities. "
        "Use check_pii() to scan text before sending it externally. "
        "Use apply_guardrails() before executing sensitive actions. "
        "Use log_action() to maintain an audit trail of all agent activities. "
        "Use check_compliance() to verify regulatory requirements. "
        "Use emergency_stop() when an agent needs to be halted immediately."
    ),
)

# Tools registrieren
from src.tools.policy import register_tools  # noqa: E402

register_tools(mcp)


def main():
    """Server starten."""
    mcp.run()


if __name__ == "__main__":
    main()
