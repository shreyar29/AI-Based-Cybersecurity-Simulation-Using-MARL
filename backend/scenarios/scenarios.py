SCENARIOS = {

    # =========================================================
    # 1️⃣ Reconnaissance to Initial Breach
    # =========================================================
    1: {
        "id": 1,
        "name": "Reconnaissance to Initial Breach",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "Attacker performs network reconnaissance."},
            {"step": 2, "actor": "defender", "narration": "Firewall logs abnormal scan patterns."},
            {"step": 3, "actor": "attacker", "target": "Firewall", "narration": "Attacker probes firewall rules."},
            {"step": 4, "actor": "soc", "narration": "SOC detects early reconnaissance indicators."},
            {"step": 5, "actor": "attacker", "target": "Server", "narration": "Attacker exploits exposed service."},
            {"step": 6, "actor": "defender", "narration": "Firewall applies temporary rate limiting."},
            {"step": 7, "actor": "attacker", "target": "Database", "narration": "Attacker attempts lateral movement."},
            {"step": 8, "actor": "soc", "narration": "SOC correlates multi-stage intrusion."},
            {"step": 9, "actor": "defender", "narration": "Firewall blocks attacker IP."},
            {"step": 10, "actor": "soc", "narration": "Incident response initiated."}
        ]
    },

    # =========================================================
    # 2️⃣ Firewall Breach Attack
    # =========================================================
    2: {
        "id": 2,
        "name": "Firewall Breach Attack",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Firewall", "narration": "Attacker launches firewall attack."},
            {"step": 2, "actor": "defender", "narration": "Firewall detects malformed packets."},
            {"step": 3, "actor": "attacker", "target": "Firewall", "narration": "Attacker exploits firewall vulnerability."},
            {"step": 4, "actor": "soc", "narration": "SOC receives critical firewall alert."},
            {"step": 5, "actor": "attacker", "target": "Server", "narration": "Attacker bypasses firewall controls."},
            {"step": 6, "actor": "defender", "narration": "Firewall reloads security rules."},
            {"step": 7, "actor": "attacker", "target": "Database", "narration": "Attacker scans internal database."},
            {"step": 8, "actor": "soc", "narration": "SOC escalates alert severity."},
            {"step": 9, "actor": "defender", "narration": "Network access restricted."},
            {"step": 10, "actor": "soc", "narration": "Firewall breach contained."}
        ]
    },

    # =========================================================
    # 3️⃣ Insider Data Exfiltration
    # =========================================================
    3: {
        "id": 3,
        "name": "Insider Data Exfiltration",
        "steps": [
            {"step": 1, "actor": "insider", "target": "Server", "narration": "Insider logs into internal server."},
            {"step": 2, "actor": "defender", "narration": "Firewall observes trusted access."},
            {"step": 3, "actor": "insider", "target": "Database", "narration": "Insider accesses sensitive records."},
            {"step": 4, "actor": "soc", "narration": "SOC notices unusual access time."},
            {"step": 5, "actor": "insider", "target": "Database", "narration": "Insider copies confidential data."},
            {"step": 6, "actor": "attacker", "target": "Server", "narration": "External attacker coordinates with insider."},
            {"step": 7, "actor": "soc", "narration": "SOC detects insider threat behavior."},
            {"step": 8, "actor": "defender", "narration": "Firewall blocks insider account."},
            {"step": 9, "actor": "soc", "narration": "Insider credentials revoked."},
            {"step": 10, "actor": "soc", "narration": "Data exfiltration prevented."}
        ]
    },

    # =========================================================
    # 4️⃣ Privilege Escalation Attack
    # =========================================================
    4: {
        "id": 4,
        "name": "Privilege Escalation Attack",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "Attacker gains low-level access."},
            {"step": 2, "actor": "defender", "narration": "Firewall logs suspicious login."},
            {"step": 3, "actor": "attacker", "target": "Server", "narration": "Attacker exploits privilege escalation bug."},
            {"step": 4, "actor": "soc", "narration": "SOC flags abnormal permission changes."},
            {"step": 5, "actor": "attacker", "target": "Firewall", "narration": "Attacker disables security controls."},
            {"step": 6, "actor": "defender", "narration": "Firewall attempts self-recovery."},
            {"step": 7, "actor": "attacker", "target": "Database", "narration": "Attacker accesses restricted data."},
            {"step": 8, "actor": "soc", "narration": "SOC confirms privilege escalation."},
            {"step": 9, "actor": "defender", "narration": "Admin access revoked."},
            {"step": 10, "actor": "soc", "narration": "System restored to safe state."}
        ]
    },

    # =========================================================
    # 5️⃣ Lateral Movement Attack
    # =========================================================
    5: {
        "id": 5,
        "name": "Lateral Movement Attack",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "Attacker compromises one server."},
            {"step": 2, "actor": "defender", "narration": "Firewall logs east-west traffic."},
            {"step": 3, "actor": "attacker", "target": "Firewall", "narration": "Attacker scans internal network."},
            {"step": 4, "actor": "soc", "narration": "SOC identifies lateral movement."},
            {"step": 5, "actor": "attacker", "target": "Database", "narration": "Attacker moves toward database."},
            {"step": 6, "actor": "defender", "narration": "Firewall restricts internal access."},
            {"step": 7, "actor": "attacker", "target": "Database", "narration": "Unauthorized database query executed."},
            {"step": 8, "actor": "soc", "narration": "SOC raises lateral movement alert."},
            {"step": 9, "actor": "defender", "narration": "Network segmentation enforced."},
            {"step": 10, "actor": "soc", "narration": "Attack path neutralized."}
        ]
    },

    # =========================================================
    # 6️⃣ Database Breach
    # =========================================================
    6: {
        "id": 6,
        "name": "Database Breach",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Database", "narration": "Attacker targets database directly."},
            {"step": 2, "actor": "defender", "narration": "Firewall detects SQL injection attempt."},
            {"step": 3, "actor": "attacker", "target": "Database", "narration": "Injection bypass successful."},
            {"step": 4, "actor": "soc", "narration": "SOC detects database anomaly."},
            {"step": 5, "actor": "insider", "target": "Database", "narration": "Insider assists attacker."},
            {"step": 6, "actor": "defender", "narration": "Firewall blocks outgoing data."},
            {"step": 7, "actor": "attacker", "target": "Database", "narration": "Partial data extraction attempted."},
            {"step": 8, "actor": "soc", "narration": "SOC triggers emergency response."},
            {"step": 9, "actor": "defender", "narration": "Database isolated."},
            {"step": 10, "actor": "soc", "narration": "Breach impact minimized."}
        ]
    },

    # =========================================================
    # 7️⃣ DDoS Attack
    # =========================================================
    7: {
        "id": 7,
        "name": "DDoS Attack",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "DDoS traffic flood begins."},
            {"step": 2, "actor": "defender", "narration": "Firewall detects traffic surge."},
            {"step": 3, "actor": "attacker", "target": "Server", "narration": "Attack intensity increases."},
            {"step": 4, "actor": "soc", "narration": "SOC confirms DDoS attack."},
            {"step": 5, "actor": "defender", "narration": "Rate limiting enabled."},
            {"step": 6, "actor": "attacker", "target": "Server", "narration": "Botnet adapts attack."},
            {"step": 7, "actor": "soc", "narration": "SOC activates mitigation plan."},
            {"step": 8, "actor": "defender", "narration": "Traffic filtering applied."},
            {"step": 9, "actor": "soc", "narration": "Service stability restored."},
            {"step": 10, "actor": "soc", "narration": "DDoS attack mitigated."}
        ]
    },

    # =========================================================
    # 8️⃣ SOC Incident Response
    # =========================================================
    8: {
        "id": 8,
        "name": "SOC Incident Response",
        "steps": [
            {"step": 1, "actor": "soc", "narration": "SOC receives multiple alerts."},
            {"step": 2, "actor": "defender", "narration": "Firewall forwards logs."},
            {"step": 3, "actor": "soc", "narration": "SOC correlates attack vectors."},
            {"step": 4, "actor": "attacker", "target": "Server", "narration": "Attacker attempts persistence."},
            {"step": 5, "actor": "defender", "narration": "Firewall blocks suspicious session."},
            {"step": 6, "actor": "soc", "narration": "SOC isolates affected systems."},
            {"step": 7, "actor": "insider", "narration": "Insider access reviewed."},
            {"step": 8, "actor": "soc", "narration": "Forensic analysis initiated."},
            {"step": 9, "actor": "defender", "narration": "System patches applied."},
            {"step": 10, "actor": "soc", "narration": "Incident fully resolved."}
        ]
    },

    # =========================================================
    # 9️⃣ Zero-Day Exploit
    # =========================================================
    9: {
        "id": 9,
        "name": "Zero-Day Exploit",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "Attacker exploits zero-day vulnerability."},
            {"step": 2, "actor": "defender", "narration": "Firewall fails to detect exploit."},
            {"step": 3, "actor": "attacker", "target": "Firewall", "narration": "Security controls bypassed."},
            {"step": 4, "actor": "soc", "narration": "SOC notices unknown behavior."},
            {"step": 5, "actor": "attacker", "target": "Database", "narration": "Attacker accesses database silently."},
            {"step": 6, "actor": "insider", "narration": "Insider unknowingly assists attack."},
            {"step": 7, "actor": "soc", "narration": "SOC identifies zero-day signature."},
            {"step": 8, "actor": "defender", "narration": "Emergency firewall rule deployed."},
            {"step": 9, "actor": "soc", "narration": "Exploit contained."},
            {"step": 10, "actor": "soc", "narration": "Zero-day mitigated."}
        ]
    },

    # =========================================================
    # 🔟 Coordinated Multi-Agent Attack
    # =========================================================
    10: {
        "id": 10,
        "name": "Coordinated Multi-Agent Attack",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "External attacker breaches server."},
            {"step": 2, "actor": "insider", "target": "Firewall", "narration": "Insider weakens firewall rules."},
            {"step": 3, "actor": "defender", "narration": "Firewall integrity compromised."},
            {"step": 4, "actor": "attacker", "target": "Database", "narration": "Attacker reaches database."},
            {"step": 5, "actor": "soc", "narration": "SOC detects coordinated attack."},
            {"step": 6, "actor": "insider", "target": "Database", "narration": "Insider assists data theft."},
            {"step": 7, "actor": "defender", "narration": "Firewall blocks data exfiltration."},
            {"step": 8, "actor": "soc", "narration": "Critical incident declared."},
            {"step": 9, "actor": "defender", "narration": "Network isolated."},
            {"step": 10, "actor": "soc", "narration": "Coordinated attack neutralized."}
        ]
    }

}
