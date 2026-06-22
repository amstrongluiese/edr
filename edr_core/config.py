from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
REPORT_DIR = BASE_DIR / "reports"
THREAT_INTEL_DIR = BASE_DIR / "threat_intel"
ARCHIVE_DIR = BASE_DIR / "archives"
DB_PATH = DATA_DIR / "edr.sqlite3"

RISK_WEIGHTS = {
    "unknown_device": 5,
    "new_device": 5,
    "risky_open_port": 15,
    "repeated_connections": 20,
    "suspicious_dns": 25,
    "beaconing": 30,
    "port_scan": 30,
    "traffic_spike": 20,
    "malicious_ip": 40,
    "malicious_domain": 40,
    "malicious_hash": 50,
    "critical_cve": 50,
    "suspicious_process": 25,
    "suspicious_file_path": 15,
    "unsigned_executable": 15,
    "startup_persistence": 15,
    "failed_attempts": 30,
    "successful_login_after_failures": 40,
    "database_access_attempt": 30,
    "malicious_url": 40,
    "possible_doh": 20,
}

RISKY_PORTS = {21, 23, 135, 139, 445, 3389, 5900, 5985, 5986}

SUSPICIOUS_TLDS = {".xyz", ".top", ".zip", ".mov", ".click", ".country"}

MITRE_MAP = {
    "beaconing": ("Command and Control", "Application Layer Protocol", "T1071"),
    "port_scan": ("Discovery", "Network Service Discovery", "T1046"),
    "suspicious_dns": ("Command and Control", "Domain Generation Algorithms", "T1568.002"),
    "malicious_ip": ("Command and Control", "Ingress Tool Transfer", "T1105"),
    "malicious_domain": ("Command and Control", "Application Layer Protocol", "T1071"),
    "malicious_hash": ("Execution", "User Execution", "T1204"),
    "critical_cve": ("Initial Access", "Exploit Public-Facing Application", "T1190"),
    "suspicious_process": ("Defense Evasion", "Masquerading", "T1036"),
    "risky_open_port": ("Discovery", "System Service Discovery", "T1007"),
    "repeated_connections": ("Command and Control", "Non-Application Layer Protocol", "T1095"),
    "traffic_spike": ("Exfiltration", "Exfiltration Over Network Medium", "T1041"),
    "unknown_device": ("Discovery", "Network Share Discovery", "T1135"),
    "new_device": ("Discovery", "Network Share Discovery", "T1135"),
    "suspicious_file_path": ("Defense Evasion", "Masquerading", "T1036"),
    "unsigned_executable": ("Defense Evasion", "Subvert Trust Controls", "T1553"),
    "startup_persistence": ("Persistence", "Registry Run Keys / Startup Folder", "T1060"),
    "failed_attempts": ("Credential Access", "Brute Force", "T1110"),
    "successful_login_after_failures": ("Credential Access", "Brute Force", "T1110"),
    "database_access_attempt": ("Collection", "Data from Information Repositories", "T1213"),
    "malicious_url": ("Command and Control", "Application Layer Protocol", "T1071"),
    "possible_doh": ("Command and Control", "Application Layer Protocol", "T1071"),
}

SCAN_PATH_NAMES = ["Downloads", "Desktop", "Documents", "AppData\\Roaming", "AppData\\Local\\Temp"]
MONITORED_EXTENSIONS = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jar", ".scr", ".msi"}
SUSPICIOUS_PATH_MARKERS = ["\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\downloads\\", "\\startup\\"]
DOH_DOMAINS = {"cloudflare-dns.com", "dns.google", "dns.quad9.net", "dns.nextdns.io", "mozilla.cloudflare-dns.com"}
