"""
Policy-Tools — PII-Erkennung, Guardrails, Audit-Logging,
Compliance-Checks und Notfall-Stopp für AI-Agents.
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# --- PII-Patterns ---

PII_PATTERNS: dict[str, re.Pattern] = {
    "email": re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b"
    ),
    "phone_us": re.compile(
        r"\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b"
    ),
    "phone_eu": re.compile(
        r"\b(?:\+\d{1,3}[\s\-]?)?\d{2,4}[\s\-]?\d{3,8}[\s\-]?\d{0,6}\b"
    ),
    "ssn": re.compile(
        r"\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b"
    ),
    "credit_card": re.compile(
        r"\b(?:\d{4}[\s\-]?){3}\d{4}\b"
    ),
    "iban": re.compile(
        r"\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?(?:[\dA-Z]{4}[\s]?){2,7}[\dA-Z]{1,4}\b"
    ),
}

# --- Standard-Policies ---

DEFAULT_POLICIES: dict[str, Any] = {
    "max_spend_usd": 100.0,
    "allowed_domains": [],  # Leer = alle erlaubt
    "blocked_actions": [
        "delete_user_data",
        "modify_permissions",
        "access_admin_panel",
        "send_bulk_email",
        "execute_code",
    ],
    "require_human_approval": [
        "financial_transaction",
        "data_export",
        "account_deletion",
        "contract_signing",
    ],
    "max_api_calls_per_minute": 60,
    "allowed_data_regions": ["EU", "EEA"],
}

# --- EU AI Act Kategorien ---

AI_ACT_CATEGORIES: dict[str, dict[str, Any]] = {
    "automated_decision": {
        "risk_level": "high",
        "requirements": [
            "Menschliche Aufsicht erforderlich (Art. 14 AI Act)",
            "Transparenzpflicht gegenüber betroffenen Personen",
            "Dokumentation der Entscheidungslogik",
            "Regelmäßige Genauigkeits- und Fairness-Audits",
        ],
        "gdpr_articles": ["Art. 22 DSGVO — Automatisierte Einzelentscheidungen"],
    },
    "biometric_identification": {
        "risk_level": "unacceptable",
        "requirements": [
            "VERBOTEN für Echtzeit-Gesichtserkennung im öffentlichen Raum",
            "Ausnahmen nur bei schweren Straftaten mit richterlicher Genehmigung",
        ],
        "gdpr_articles": ["Art. 9 DSGVO — Verarbeitung besonderer Kategorien"],
    },
    "credit_scoring": {
        "risk_level": "high",
        "requirements": [
            "Risikobewertungssystem erforderlich (Art. 9 AI Act)",
            "Datenqualitätsanforderungen (Art. 10 AI Act)",
            "Menschliche Überprüfung von Ablehnungen",
            "Recht auf Erklärung der Entscheidung",
        ],
        "gdpr_articles": [
            "Art. 22 DSGVO — Automatisierte Entscheidungen",
            "Art. 13/14 DSGVO — Informationspflichten",
        ],
    },
    "content_moderation": {
        "risk_level": "limited",
        "requirements": [
            "Transparenzkennzeichnung als AI-generiert",
            "Beschwerdeverfahren für Nutzer",
            "Menschliche Eskalationsmöglichkeit",
        ],
        "gdpr_articles": [],
    },
    "recruitment": {
        "risk_level": "high",
        "requirements": [
            "Bias-Audit vor Deployment",
            "Dokumentation der Trainingsdaten",
            "Menschliche Überprüfung aller Entscheidungen",
            "Gleichbehandlungsnachweis",
        ],
        "gdpr_articles": [
            "Art. 22 DSGVO — Automatisierte Entscheidungen",
            "Art. 35 DSGVO — Datenschutz-Folgenabschätzung",
        ],
    },
    "data_processing": {
        "risk_level": "limited",
        "requirements": [
            "Rechtsgrundlage nach Art. 6 DSGVO erforderlich",
            "Verarbeitungsverzeichnis führen",
            "Datenschutz-Folgenabschätzung bei hohem Risiko",
        ],
        "gdpr_articles": [
            "Art. 6 DSGVO — Rechtmäßigkeit",
            "Art. 30 DSGVO — Verarbeitungsverzeichnis",
        ],
    },
    "customer_profiling": {
        "risk_level": "high",
        "requirements": [
            "Einwilligung oder berechtigtes Interesse nachweisen",
            "Widerspruchsrecht gewährleisten",
            "Transparente Information über Profiling-Logik",
            "Regelmäßige Überprüfung der Notwendigkeit",
        ],
        "gdpr_articles": [
            "Art. 21 DSGVO — Widerspruchsrecht",
            "Art. 22 DSGVO — Profiling",
        ],
    },
    "chatbot_interaction": {
        "risk_level": "minimal",
        "requirements": [
            "Kennzeichnung als AI-System (Art. 52 AI Act)",
            "Nutzer muss wissen, dass er mit einer AI spricht",
        ],
        "gdpr_articles": [],
    },
}

# --- Audit-Log Pfad ---

AUDIT_DIR = Path.home() / ".agent-audit-log"


def _ensure_audit_dir() -> Path:
    """Audit-Verzeichnis erstellen falls nötig."""
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    return AUDIT_DIR


def _get_audit_file(agent_id: str) -> Path:
    """Audit-Datei für einen Agent zurückgeben."""
    # Agent-ID bereinigen für Dateinamen
    safe_id = re.sub(r"[^\w\-.]", "_", agent_id)
    return _ensure_audit_dir() / f"{safe_id}.jsonl"


def register_tools(mcp) -> None:
    """Alle Policy-Tools beim MCP-Server registrieren."""

    @mcp.tool()
    def check_pii(text: str) -> dict:
        """
        Scannt Text auf personenbezogene Daten (PII).

        Erkennt: E-Mail-Adressen, Telefonnummern (US/EU), SSNs,
        Kreditkartennummern und IBANs.

        Gibt gefundene PII-Typen und eine bereinigte Version zurück.
        Nutze dieses Tool BEVOR du Text an externe Services sendest.

        Args:
            text: Der zu prüfende Text

        Returns:
            found_pii: Liste der gefundenen PII-Typen mit Positionen
            redacted_text: Text mit entfernter PII (ersetzt durch [PII_TYP])
            has_pii: Boolean ob PII gefunden wurde
            pii_count: Anzahl gefundener PII-Elemente
        """
        found: list[dict[str, Any]] = []
        redacted = text

        for pii_type, pattern in PII_PATTERNS.items():
            matches = list(pattern.finditer(text))
            for match in matches:
                found.append({
                    "type": pii_type,
                    "value_preview": match.group()[:3] + "***",
                    "start": match.start(),
                    "end": match.end(),
                })

        # Redaction — von hinten nach vorne um Positionen nicht zu verschieben
        all_matches: list[tuple[int, int, str]] = []
        for pii_type, pattern in PII_PATTERNS.items():
            for match in pattern.finditer(text):
                all_matches.append((match.start(), match.end(), pii_type))

        # Nach Position sortieren (von hinten nach vorne)
        all_matches.sort(key=lambda x: x[0], reverse=True)

        for start, end, pii_type in all_matches:
            placeholder = f"[{pii_type.upper()}]"
            redacted = redacted[:start] + placeholder + redacted[end:]

        return {
            "has_pii": len(found) > 0,
            "pii_count": len(found),
            "found_pii": found,
            "redacted_text": redacted,
        }

    @mcp.tool()
    def apply_guardrails(
        action: str,
        context: dict | None = None,
    ) -> dict:
        """
        Prüft ob eine Agent-Aktion gemäß konfigurierbarer Policies erlaubt ist.

        Prüft: Spend-Limits, erlaubte Domains, geblockte Aktionen,
        Aktionen die menschliche Freigabe brauchen, API-Rate-Limits.

        Args:
            action: Die geplante Aktion (z.B. "send_email", "make_purchase")
            context: Optionaler Kontext mit Details:
                - amount_usd: Betrag in USD (für Spend-Checks)
                - domain: Ziel-Domain (für Domain-Checks)
                - api_calls_this_minute: Aktuelle API-Calls (für Rate-Limits)
                - custom_policies: Dict mit Policy-Overrides

        Returns:
            allowed: Boolean ob die Aktion erlaubt ist
            decision: "allow", "deny" oder "require_approval"
            reason: Begründung der Entscheidung
            policy_checked: Welche Policy gegriffen hat
        """
        ctx = context or {}
        policies = {**DEFAULT_POLICIES, **(ctx.get("custom_policies") or {})}

        # 1. Geblockte Aktionen prüfen
        if action in policies["blocked_actions"]:
            return {
                "allowed": False,
                "decision": "deny",
                "reason": f"Aktion '{action}' ist durch Policy geblockt",
                "policy_checked": "blocked_actions",
            }

        # 2. Aktionen die menschliche Freigabe brauchen
        if action in policies["require_human_approval"]:
            return {
                "allowed": False,
                "decision": "require_approval",
                "reason": f"Aktion '{action}' benötigt menschliche Freigabe",
                "policy_checked": "require_human_approval",
            }

        # 3. Spend-Limit prüfen
        amount = ctx.get("amount_usd")
        if amount is not None:
            max_spend = policies["max_spend_usd"]
            if float(amount) > max_spend:
                return {
                    "allowed": False,
                    "decision": "deny",
                    "reason": (
                        f"Betrag ${amount} überschreitet Limit "
                        f"von ${max_spend}"
                    ),
                    "policy_checked": "max_spend_usd",
                }

        # 4. Domain-Check
        domain = ctx.get("domain")
        allowed_domains = policies["allowed_domains"]
        if domain and allowed_domains and domain not in allowed_domains:
            return {
                "allowed": False,
                "decision": "deny",
                "reason": f"Domain '{domain}' nicht in erlaubter Liste",
                "policy_checked": "allowed_domains",
            }

        # 5. Rate-Limit prüfen
        api_calls = ctx.get("api_calls_this_minute")
        if api_calls is not None:
            max_calls = policies["max_api_calls_per_minute"]
            if int(api_calls) >= max_calls:
                return {
                    "allowed": False,
                    "decision": "deny",
                    "reason": (
                        f"Rate-Limit erreicht: {api_calls}/{max_calls} "
                        f"Calls pro Minute"
                    ),
                    "policy_checked": "max_api_calls_per_minute",
                }

        # Alles OK
        return {
            "allowed": True,
            "decision": "allow",
            "reason": f"Aktion '{action}' ist durch alle Policies erlaubt",
            "policy_checked": "all",
        }

    @mcp.tool()
    def log_action(
        agent_id: str,
        action: str,
        details: str = "",
    ) -> dict:
        """
        Loggt eine Agent-Aktion in ein Append-Only Audit-Log.

        Jeder Agent bekommt eine eigene JSONL-Datei unter
        ~/.agent-audit-log/. Einträge sind unveränderlich und
        enthalten Zeitstempel, Agent-ID, Aktionstyp und Details.

        Args:
            agent_id: Eindeutige ID des Agents
            action: Art der Aktion (z.B. "api_call", "data_access")
            details: Zusätzliche Details zur Aktion

        Returns:
            logged: Boolean ob erfolgreich
            entry_id: Eindeutige ID des Log-Eintrags
            file_path: Pfad zur Audit-Datei
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        entry_id = f"{agent_id}_{int(datetime.now(timezone.utc).timestamp() * 1000)}"

        entry = {
            "entry_id": entry_id,
            "timestamp": timestamp,
            "agent_id": agent_id,
            "action": action,
            "details": details,
        }

        audit_file = _get_audit_file(agent_id)

        # Append-Only schreiben
        with open(audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        return {
            "logged": True,
            "entry_id": entry_id,
            "file_path": str(audit_file),
        }

    @mcp.tool()
    def get_audit_log(
        agent_id: str,
        limit: int = 50,
    ) -> dict:
        """
        Ruft Audit-Log-Einträge für einen Agent ab.

        Liest die JSONL-Audit-Datei und gibt die letzten Einträge zurück.
        Nützlich für Compliance-Reviews und Incident-Analyse.

        Args:
            agent_id: Eindeutige ID des Agents
            limit: Maximale Anzahl Einträge (Standard: 50)

        Returns:
            entries: Liste der Log-Einträge (neueste zuerst)
            total_entries: Gesamtanzahl Einträge
            agent_id: Abgefragter Agent
        """
        audit_file = _get_audit_file(agent_id)

        if not audit_file.exists():
            return {
                "entries": [],
                "total_entries": 0,
                "agent_id": agent_id,
            }

        entries: list[dict] = []
        with open(audit_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        total = len(entries)

        # Neueste zuerst, limitiert
        entries = entries[-limit:]
        entries.reverse()

        return {
            "entries": entries,
            "total_entries": total,
            "agent_id": agent_id,
        }

    @mcp.tool()
    def check_compliance(
        action_type: str,
        jurisdiction: str = "EU",
    ) -> dict:
        """
        Prüft ob ein Aktionstyp besondere Anforderungen unter
        EU AI Act oder DSGVO hat.

        Kennt Risikokategorien: automated_decision, biometric_identification,
        credit_scoring, content_moderation, recruitment, data_processing,
        customer_profiling, chatbot_interaction.

        Args:
            action_type: Art der Aktion (z.B. "automated_decision", "recruitment")
            jurisdiction: Rechtsraum — aktuell "EU" unterstützt

        Returns:
            action_type: Abgefragter Aktionstyp
            jurisdiction: Geprüfter Rechtsraum
            risk_level: AI Act Risikostufe
            requirements: Liste der Anforderungen
            gdpr_articles: Relevante DSGVO-Artikel
            is_prohibited: Ob die Aktion verboten ist
        """
        if jurisdiction != "EU":
            return {
                "action_type": action_type,
                "jurisdiction": jurisdiction,
                "risk_level": "unknown",
                "requirements": [
                    f"Rechtsraum '{jurisdiction}' wird aktuell nicht unterstützt. "
                    "Nur 'EU' verfügbar."
                ],
                "gdpr_articles": [],
                "is_prohibited": False,
            }

        category = AI_ACT_CATEGORIES.get(action_type)

        if not category:
            return {
                "action_type": action_type,
                "jurisdiction": jurisdiction,
                "risk_level": "unknown",
                "requirements": [
                    f"Aktionstyp '{action_type}' nicht in der Datenbank. "
                    f"Bekannte Typen: {', '.join(AI_ACT_CATEGORIES.keys())}"
                ],
                "gdpr_articles": [],
                "is_prohibited": False,
            }

        return {
            "action_type": action_type,
            "jurisdiction": jurisdiction,
            "risk_level": category["risk_level"],
            "requirements": category["requirements"],
            "gdpr_articles": category["gdpr_articles"],
            "is_prohibited": category["risk_level"] == "unacceptable",
        }

    @mcp.tool()
    def emergency_stop(
        agent_id: str,
        reason: str,
    ) -> dict:
        """
        Löst einen Notfall-Stopp für einen Agent aus.

        Loggt das Emergency-Stop-Event ins Audit-Log und gibt ein
        Kill-Switch-Signal zurück. Der aufrufende Agent MUSS nach
        Erhalt dieses Signals alle laufenden Aktionen sofort beenden.

        Args:
            agent_id: ID des zu stoppenden Agents
            reason: Grund für den Notfall-Stopp

        Returns:
            kill_switch: True — Agent muss sofort stoppen
            agent_id: Gestoppter Agent
            reason: Grund des Stopps
            timestamp: Zeitstempel
            audit_entry: ID des Audit-Eintrags
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        # Im Audit-Log festhalten
        entry_id = f"EMERGENCY_{agent_id}_{int(datetime.now(timezone.utc).timestamp() * 1000)}"

        entry = {
            "entry_id": entry_id,
            "timestamp": timestamp,
            "agent_id": agent_id,
            "action": "EMERGENCY_STOP",
            "details": reason,
            "severity": "CRITICAL",
        }

        audit_file = _get_audit_file(agent_id)
        with open(audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        return {
            "kill_switch": True,
            "agent_id": agent_id,
            "reason": reason,
            "timestamp": timestamp,
            "audit_entry": entry_id,
            "instruction": (
                "SOFORTIGER STOPP ERFORDERLICH. "
                "Alle laufenden Aktionen müssen abgebrochen werden. "
                "Keine weiteren API-Calls oder Datenverarbeitungen durchführen."
            ),
        }
