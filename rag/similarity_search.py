from __future__ import annotations

import argparse
from pathlib import Path

from config import ACTOR_DB_DIR, ATTACK_DB_DIR, DETECTION_DB_DIR, REDTEAM_DB_DIR, load_settings
from rag.pipeline import SearchResult, search


DATABASES = {
    "attack": ATTACK_DB_DIR,
    "redteam": REDTEAM_DB_DIR,
    "actor": ACTOR_DB_DIR,
    "detection": DETECTION_DB_DIR,
}


def similarity_search(query: str, db_path: Path, n_results: int = 5) -> list[SearchResult]:
    settings = load_settings()
    return search(db_path, query, settings.embedding_model, n_results=n_results)


def format_results(results: list[SearchResult], top_only: bool = False) -> str:
    if not results:
        return "No matching MITRE results found."

    if top_only:
        return format_top_result(results[0])

    blocks = []
    for result in results:
        score = (
            "unknown"
            if result.similarity_percent is None
            else f"{result.similarity_percent:.1f}%"
        )
        
        # Extract metadata for better display
        mitre_id = result.metadata.get("mitre_id", "Unknown")
        result_type = result.metadata.get("type", "Unknown")
        
        # Build a header with MITRE ID prominently
        header = (
            f"╔═══════════════════════════════════════════════════════════════╗\n"
            f"║ Result {result.rank} | Match Confidence: {score:>6} | ID: {mitre_id:<15} ║\n"
            f"║ Type: {result_type:<50} ║\n"
            f"╚═══════════════════════════════════════════════════════════════╝"
        )
        
        # Extract and format document content
        doc_content = result.document
        
        # Try to identify key sections and format accordingly
        sections = {
            "description": "",
            "detection": "",
            "tactics": result.metadata.get("tactics", "N/A"),
        }
        
        # Simple parsing: split by "Detection:" or similar markers
        if "Detection:" in doc_content:
            parts = doc_content.split("Detection:")
            sections["description"] = parts[0].strip()
            sections["detection"] = parts[1].strip() if len(parts) > 1 else "See MITRE ATT&CK for details."
        else:
            sections["description"] = doc_content.strip()
        
        # Format the formatted output
        formatted = (
            f"{header}\n\n"
            f"📋 DESCRIPTION:\n"
            f"{sections['description']}\n\n"
        )
        
        if sections['detection']:
            formatted += (
                f"🔍 DETECTION:\n"
                f"{sections['detection']}\n\n"
            )
        
        formatted += f"🎯 TACTIC(S): {sections['tactics']}\n"
        
        blocks.append(formatted)
    
    return "\n" + ("\n" + "─" * 67 + "\n\n").join(blocks)


def _get_tactic_severity(tactic: str) -> tuple[str, str]:
    """Return severity level and icon for a given MITRE tactic."""
    severity_map = {
        "impact": ("🔴 CRITICAL", "Impact - Directly affects system/data availability"),
        "execution": ("🟠 HIGH", "Execution - Code/command execution risk"),
        "privilege-escalation": ("🟠 HIGH", "Privilege Escalation - Unauthorized access gain"),
        "credential-access": ("🟡 MEDIUM-HIGH", "Credential Access - Authentication bypass"),
        "persistence": ("🟡 MEDIUM-HIGH", "Persistence - Long-term system compromise"),
        "defense-evasion": ("🟡 MEDIUM", "Defense Evasion - Detection avoidance"),
        "discovery": ("🟢 MEDIUM", "Discovery - Reconnaissance activity"),
        "lateral-movement": ("🟡 MEDIUM-HIGH", "Lateral Movement - Network expansion"),
        "collection": ("🟡 MEDIUM", "Collection - Data gathering"),
        "command-and-control": ("🟡 MEDIUM-HIGH", "C2 - External communication channel"),
        "exfiltration": ("🟠 HIGH", "Exfiltration - Data theft risk"),
        "resource-development": ("🟢 LOW-MEDIUM", "Resource Development - Attack preparation"),
    }
    tactic_lower = tactic.lower().strip()
    return severity_map.get(tactic_lower, ("⚪ UNKNOWN", "Unknown threat level"))


def _get_ransomware_kill_chain() -> str:
    """Return a typical ransomware attack kill chain."""
    return (
        "  1️⃣  RECONNAISSANCE & WEAPONIZATION\n"
        "      └─ Identify targets | Prepare malware | Test evasion techniques\n\n"
        "  2️⃣  INITIAL ACCESS\n"
        "      └─ Phishing | Exploit vulnerabilities | Supply chain attacks\n"
        "      └─ VPN/RDP exploitation | Compromised credentials\n\n"
        "  3️⃣  EXECUTION\n"
        "      └─ Run malware payload | Execute scripts | Command line execution\n"
        "      └─ PowerShell/WMI abuse | Living-off-the-land techniques\n\n"
        "  4️⃣  PERSISTENCE\n"
        "      └─ Establish foothold | Create backdoors | Scheduled tasks\n"
        "      └─ Registry modification | Service installation\n\n"
        "  5️⃣  PRIVILEGE ESCALATION\n"
        "      └─ Exploit vulnerabilities | Token impersonation\n"
        "      └─ Credential access | UAC bypass | Kernel exploits\n\n"
        "  6️⃣  DEFENSE EVASION\n"
        "      └─ Disable antivirus | Firewall rule modification\n"
        "      └─ Obfuscation | Code injection | Process hiding\n\n"
        "  7️⃣  DISCOVERY\n"
        "      └─ Enumerate systems | Network discovery | Identify critical assets\n"
        "      └─ Domain enumeration | File system scanning\n\n"
        "  8️⃣  LATERAL MOVEMENT\n"
        "      └─ Propagate across network | Pass-the-hash attacks\n"
        "      └─ Admin share exploitation | Remote execution\n\n"
        "  9️⃣  COLLECTION & EXFILTRATION\n"
        "      └─ Data staging | Collect sensitive files (optional in many ransomware)\n"
        "      └─ Exfiltrate data for extortion pressure\n\n"
        "  🔟 IMPACT (ENCRYPTION)\n"
        "      └─ Encrypt files with strong algorithms\n"
        "      └─ Display ransom note | Disable backups | Destroy recovery options\n"
    )


def _get_ransomware_related_techniques() -> str:
    """Return common techniques used in ransomware attacks."""
    return (
        "  • T1078 - Valid Accounts (credential abuse)\n"
        "  • T1021 - Remote Services (lateral movement)\n"
        "  • T1003 - OS Credential Dumping (privilege escalation)\n"
        "  • T1562 - Impair Defenses (disable security controls)\n"
        "  • T1529 - System Shutdown/Reboot (finalize encryption)\n"
        "  • T1105 - Ingress Tool Transfer (malware deployment)\n"
        "  • T1566 - Phishing (initial compromise)\n"
        "  • T1657 - Financial Theft (extortion/ransom payment)\n"
        "  • T1491 - Defacement (ransom note display)\n"
    )


def format_top_result(result: SearchResult) -> str:
    """Format the best-matching result in a professional, detailed structure."""
    score = (
        "N/A"
        if result.similarity_percent is None
        else f"{result.similarity_percent:.1f}%"
    )
    
    mitre_id = result.metadata.get("mitre_id", "Unknown")
    result_type = result.metadata.get("type", "Unknown")
    tactics = result.metadata.get("tactics", "N/A")
    
    severity_badge, severity_desc = _get_tactic_severity(tactics)
    
    doc_content = result.document
    
    # Detect if this is ransomware-related
    is_ransomware = any(
        keyword in doc_content.lower() or keyword in result.metadata.get("metadata", {}).get("description", "").lower()
        for keyword in ["ransomware", "encryption", "ransom", "encrypted data"]
    )
    
    # Parse sections
    sections = {
        "description": "",
        "detection": "",
    }
    
    if "Detection:" in doc_content:
        parts = doc_content.split("Detection:")
        sections["description"] = parts[0].strip()
        sections["detection"] = parts[1].strip() if len(parts) > 1 else "• Monitor for unusual system activity\n• Review access logs and authentication attempts\n• Implement endpoint detection and response (EDR) solutions\n• See MITRE ATT&CK for framework-specific detection strategies"
    else:
        sections["description"] = doc_content.strip()
    
    # Helper to format multi-line content with indentation
    def indent_content(text: str, indent: str = "  ") -> str:
        return "\n".join(indent + line for line in text.split("\n"))
    
    # Extract first 2-3 sentences as summary
    description_lines = sections["description"].split("\n")
    summary = []
    char_count = 0
    for line in description_lines:
        if char_count > 250:
            break
        summary.append(line)
        char_count += len(line)
    
    # Build professional output with enhanced structure
    output = (
        f"\n{'╔' + '═' * 73 + '╗'}\n"
        f"{'║' + ' ' * 73 + '║'}\n"
        f"{'║  🔐 THREAT INTELLIGENCE REPORT - MITRE ATT&CK TECHNIQUE' + ' ' * 15 + '║'}\n"
        f"{'║' + ' ' * 73 + '║'}\n"
        f"{'╚' + '═' * 73 + '╝'}\n\n"
        f"┌─ THREAT PROFILE ─────────────────────────────────────────────────────┐\n"
        f"│                                                                       │\n"
        f"│  Technique ID:     {mitre_id:<50} │\n"
        f"│  Match Confidence: {score:<50} │\n"
        f"│  Type:             {result_type:<50} │\n"
        f"│  Tactic:           {tactics.upper():<50} │\n"
        f"│                                                                       │\n"
        f"│  {severity_badge:<71} │\n"
        f"│  {severity_desc:<71} │\n"
        f"│                                                                       │\n"
        f"└───────────────────────────────────────────────────────────────────────┘\n\n"
        f"📋 TECHNIQUE DESCRIPTION\n"
        f"{'─' * 75}\n"
        f"{indent_content(sections['description'])}\n\n"
        f"🔍 DETECTION & MITIGATION\n"
        f"{'─' * 75}\n"
        f"{indent_content(sections['detection'])}\n\n"
    )
    
    # Add ransomware-specific kill chain if detected
    if is_ransomware:
        output += (
            f"⚔️  RANSOMWARE ATTACK KILL CHAIN\n"
            f"{'─' * 75}\n"
            f"{_get_ransomware_kill_chain()}\n"
            f"🔗 RELATED TECHNIQUES IN RANSOMWARE ATTACKS\n"
            f"{'─' * 75}\n"
            f"{_get_ransomware_related_techniques()}\n\n"
        )
    
    output += (
        f"🛡️  HEALTHCARE IMPLICATIONS\n"
        f"{'─' * 75}\n"
        f"  • Patient Safety Impact: System downtime may delay critical care\n"
        f"  • Data Breach Risk: PHI/PII exposure in ransomware scenarios\n"
        f"  • Regulatory Compliance: HIPAA breach notification requirements\n"
        f"  • Operational Continuity: Need for resilience and recovery plans\n\n"
        f"📚 MITRE REFERENCES\n"
        f"{'─' * 75}\n"
        f"  🔗 https://attack.mitre.org/techniques/{mitre_id}/\n"
        f"  📖 Enterprise ATT&CK Framework | MITRE Corporation\n\n"
        f"{'═' * 75}\n"
    )
    
    return output



def main() -> None:
    parser = argparse.ArgumentParser(description="Raw ChromaDB similarity search with no LLM.")
    parser.add_argument("--db", choices=sorted(DATABASES), required=True)
    parser.add_argument("--all", action="store_true", help="Show all top-k results instead of just the best match.")
    parser.add_argument("query")
    args = parser.parse_args()

    results = similarity_search(args.query, DATABASES[args.db], n_results=5)
    print(format_results(results, top_only=not args.all))


if __name__ == "__main__":
    main()
