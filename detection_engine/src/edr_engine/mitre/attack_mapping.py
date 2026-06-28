from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from edr_engine.mitre.interfaces import MitreTechnique


@dataclass(frozen=True)
class AttackMapping:
    category: str
    tactic: str
    technique: str
    mitre_id: str

    def as_technique(self) -> MitreTechnique:
        return MitreTechnique(self.mitre_id, self.technique, self.tactic)


ATTACK_MAPPINGS = {
    "beaconing": AttackMapping("beaconing", "Command and Control", "Application Layer Protocol", "T1071"),
    "repeated_connection": AttackMapping("repeated_connection", "Command and Control", "Application Layer Protocol", "T1071"),
    "suspicious_dns": AttackMapping("suspicious_dns", "Command and Control", "DNS", "T1071.004"),
    "dns_length_anomaly": AttackMapping("dns_length_anomaly", "Command and Control", "DNS", "T1071.004"),
    "dns_tld_reputation": AttackMapping("dns_tld_reputation", "Command and Control", "DNS", "T1071.004"),
    "possible_dga": AttackMapping("possible_dga", "Command and Control", "DNS", "T1071.004"),
    "dns_transport": AttackMapping("dns_transport", "Command and Control", "DNS", "T1071.004"),
    "port_discovery": AttackMapping("port_discovery", "Discovery", "Network Service Discovery", "T1046"),
    "unknown_process": AttackMapping("unknown_process", "Defense Evasion", "Masquerading", "T1036"),
    "asset_inventory": AttackMapping("asset_inventory", "Discovery", "System Owner/User Discovery", "T1033"),
    "large_data_transfer": AttackMapping("large_data_transfer", "Exfiltration", "Exfiltration Over C2 Channel", "T1041"),
    "suspicious_network_port": AttackMapping("suspicious_network_port", "Command and Control", "Non-Standard Port", "T1571"),
    "threat_intel_ip": AttackMapping("threat_intel_ip", "Command and Control", "Application Layer Protocol", "T1071"),
    "threat_intel_domain": AttackMapping("threat_intel_domain", "Command and Control", "Domain Generation Algorithms", "T1568.002"),
    "threat_intel_url": AttackMapping("threat_intel_url", "Command and Control", "Ingress Tool Transfer", "T1105"),
    "threat_intel_hash": AttackMapping("threat_intel_hash", "Execution", "User Execution: Malicious File", "T1204.002"),
    "threat_intel_cve": AttackMapping("threat_intel_cve", "Initial Access", "Exploit Public-Facing Application", "T1190"),
    "living_off_the_land_or_scripting": AttackMapping(
        "living_off_the_land_or_scripting",
        "Execution",
        "Command and Scripting Interpreter",
        "T1059",
    ),
    "unusual_execution_location": AttackMapping("unusual_execution_location", "Execution", "User Execution", "T1204"),
}


SMB_MAPPING = AttackMapping("smb_rdp_access", "Lateral Movement", "SMB/Windows Admin Shares", "T1021.002")
RDP_MAPPING = AttackMapping("smb_rdp_access", "Lateral Movement", "Remote Desktop Protocol", "T1021.001")


class AttackMappingEngine:
    def map_category(self, category: str, metadata: dict[str, Any] | None = None) -> list[MitreTechnique]:
        metadata = metadata or {}
        if category == "smb_rdp_access":
            remote_port = int(metadata.get("remote_port") or 0)
            if remote_port == 3389:
                return [RDP_MAPPING.as_technique()]
            if remote_port == 445:
                return [SMB_MAPPING.as_technique()]
            return [SMB_MAPPING.as_technique(), RDP_MAPPING.as_technique()]

        mapping = ATTACK_MAPPINGS.get(category)
        return [mapping.as_technique()] if mapping else []
