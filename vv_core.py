# --- START OF FILE vv_core.py ---

import sqlite3
from dataclasses import dataclass
from typing import List, Optional, Dict, Tuple
from pathlib import Path

# --- BUILT-IN INTELLIGENCE (Golden Remediation Library) ---
GOLDEN_LIBRARY = {
    "Web App (OWASP Top 10)": [
        ("A01", "Broken Access Control", "Implement centralized access control; use 'Deny by Default'."),
        ("A02", "Security Misconfiguration", "Automate hardening; remove default accounts and verbose error pages."),
        ("A03", "Software/Data Integrity", "Use digital signatures for updates; verify CI/CD pipeline security."),
        ("A04", "Cryptographic Failures", "Encrypt data at rest/transit (AES-256/TLS 1.3); disable old protocols."),
        ("A05", "Injection (SQLi, XSS)", "Use parameterized queries and context-aware output encoding."),
        ("A06", "Insecure Design", "Shift-left security; perform Threat Modeling during the design phase."),
        ("A07", "Authentication Failures", "Implement Phishing-resistant MFA (FIDO2); enforce account lockouts."),
        ("A08", "Integrity Failures", "Verify plugins/libraries; use Subresource Integrity (SRI) for CDN assets."),
        ("A09", "Logging & Alerting", "Log all auth failures/high-value transactions; use a SIEM for alerts."),
        ("A10", "SSRF", "Sanitize inputs for URLs; implement strict allowlists for outbound calls.")
    ],
    "API Security (OWASP API)": [
        ("API1", "BOLA (Object Level)", "Validate that the logged-in user owns the resource requested in the URL."),
        ("API2", "Broken Authentication", "Use standard OAuth2/OpenID Connect; secure tokens with short TTLs."),
        ("API3", "BOPLA (Property Level)", "Use Data Transfer Objects (DTOs) to prevent 'Mass Assignment' of fields."),
        ("API4", "Unrestricted Consumption", "Set Rate Limits (TPS) and quotas for CPU/Memory/Payload size."),
        ("API5", "Broken Function Level", "Enforce RBAC (Role-Based Access Control) on all admin endpoints."),
        ("API6", "Unrestricted Business Logic", "Validate workflow sequences to prevent bypassing payment or approval steps."),
        ("API7", "SSRF (API Specific)", "Block API access to internal metadata services (e.g., AWS IMDS)."),
        ("API8", "Security Misconfiguration", "Disable unnecessary HTTP methods (PUT/PATCH/DELETE) and CORS wildcards."),
        ("API9", "Improper Inventory", "Maintain OpenAPI/Swagger docs; sunset 'Zombie' (old) API versions."),
        ("API10", "Unsafe Consumption", "Sanitize data from third-party APIs before processing; use strict schema validation.")
    ],
    "Mobile Security (OWASP Mobile)": [
        ("M1", "Improper Credentials", "Use Android Keystore/iOS Keychain; never hardcode API keys."),
        ("M2", "Inadequate Supply Chain", "Verify third-party SDKs; use Software Bill of Materials (SBOM) tracking."),
        ("M3", "Insecure Authentication", "Implement MFA and biometric backing; avoid local-only auth bypasses."),
        ("M4", "Insufficient Input Validation", "Sanitize data from IPC, URLs, and QR codes to prevent deep-link attacks."),
        ("M5", "Insecure Communication", "Enforce TLS; implement Certificate Pinning to stop MitM attacks."),
        ("M6", "Inadequate Privacy", "Limit PII collection; use 'Purpose Limitation' and data minimization."),
        ("M7", "Binary Protection", "Use Obfuscation (DexGuard/ProGuard) and Anti-Tampering checks."),
        ("M8", "Security Misconfiguration", "Disable Debug mode; set 'allowBackup=false' in Android Manifest."),
        ("M9", "Insecure Data Storage", "Encrypt local SQLite/Realm databases using SQLCipher."),
        ("M10", "Insufficient Cryptography", "Use modern primitives (AES-GCM/Argon2); avoid hardcoded salts.")
    ],
    "AD & Infrastructure": [
        ("AD-01", "Kerberoasting", "Use gMSAs or passwords with >25 characters for Service Accounts."),
        ("AD-02", "AS-REP Roasting", "Enable 'Do not require Kerberos preauthentication' only where necessary."),
        ("AD-03", "BloodHound Path", "Audit High-Privileged groups (Domain Admins); reduce 'Nested' permissions."),
        ("NET-01", "LLMNR/NBNS", "Disable via GPO; enable SMB Signing to prevent relaying."),
        ("INF-01", "Unquoted Service Path", "Wrap service executables in quotes: 'C:\\Program Files\\App\\srv.exe'.")
    ]
}

# --- DATA MODELS ---

@dataclass
class Finding:
    """Core Finding Model"""
    id: Optional[int]
    title: str
    description: str
    cvss_score: float = 0.0
    mitre_id: str = ""
    tactic_id: str = ""
    status: str = "Open"
    evidence: str = "" 
    remediation: str = ""

@dataclass
class MitreTechnique:
    """Intel Model"""
    id: str
    name: str
    description: str

# --- INTELLIGENCE ENGINE ---

class IntelligenceEngine:
    """
    Manages knowledge base. 
    1. Loads mitre_reference.txt if available.
    2. Provides built-in Golden Library lookups.
    """
    REFERENCE_FILE = "mitre_reference.txt"

    def __init__(self):
        self.mitre_cache: Dict[str, MitreTechnique] = {}
        self._load_mitre_reference()

    def _load_mitre_reference(self):
        path = Path(self.REFERENCE_FILE)
        if not path.exists():
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    if "|" in line:
                        parts = line.strip().split("|")
                        if len(parts) >= 2:
                            tid = parts[0].strip()
                            name = parts[1].strip()
                            desc = parts[2].strip() if len(parts) > 2 else "No description."
                            
                            tech = MitreTechnique(tid, name, desc)
                            self.mitre_cache[tid.upper()] = tech
        except Exception:
            pass

    def lookup_mitre(self, technique_id: str) -> Optional[MitreTechnique]:
        return self.mitre_cache.get(technique_id.upper())

    def get_remediation_suggestion(self, category: str) -> List[Tuple[str, str, str]]:
        """Returns list of (ID, Title, Remediation) based on category fuzzy match."""
        results = []
        for key, items in GOLDEN_LIBRARY.items():
            if category.lower() in key.lower() or key.lower() in category.lower():
                results.extend(items)
        return results

# --- CORE DATABASE MANAGER ---

class Database:
    """Primary SQLite Database"""
    DB_NAME = "vectorvue.db"

    def __init__(self):
        self.conn = sqlite3.connect(self.DB_NAME, check_same_thread=False)
        self.check_schema()

    def check_schema(self):
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS findings
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      title TEXT NOT NULL,
                      description TEXT, 
                      cvss_score REAL DEFAULT 0.0,
                      mitre_id TEXT DEFAULT '',
                      tactic_id TEXT DEFAULT '',
                      status TEXT DEFAULT 'Open',
                      evidence TEXT DEFAULT '',
                      remediation TEXT DEFAULT '')''')
        self.conn.commit()

    def get_findings(self) -> List[Finding]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM findings ORDER BY cvss_score DESC")
        rows = c.fetchall()
        # Mapping row to object assuming consistent schema order
        results = []
        for r in rows:
            try:
                results.append(Finding(
                    id=r[0], title=r[1], description=r[2], 
                    cvss_score=r[3], mitre_id=r[4], tactic_id=r[5], 
                    status=r[6], evidence=r[7], remediation=r[8]
                ))
            except IndexError:
                continue 
        return results

    def add_finding(self, f: Finding) -> int:
        c = self.conn.cursor()
        c.execute("""INSERT INTO findings 
                     (title, description, cvss_score, mitre_id, tactic_id, status, evidence, remediation) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                  (f.title, f.description, f.cvss_score, f.mitre_id, f.tactic_id, f.status, f.evidence, f.remediation))
        self.conn.commit()
        return c.lastrowid

    def update_finding(self, f: Finding):
        if not f.id: return
        c = self.conn.cursor()
        c.execute("""UPDATE findings SET 
                     title=?, description=?, cvss_score=?, mitre_id=?, status=?, evidence=?, remediation=?
                     WHERE id=?""",
                  (f.title, f.description, f.cvss_score, f.mitre_id, f.status, f.evidence, f.remediation, f.id))
        self.conn.commit()

    def delete_finding(self, fid: int):
        c = self.conn.cursor()
        c.execute("DELETE FROM findings WHERE id=?", (fid,))
        self.conn.commit()

    def close(self):
        self.conn.close()