
SCENARIOS = {
    # =========================================================
    # 1️⃣ Reconnaissance to Initial Breach (Interactive)
    # =========================================================
    1: {
        "id": 1,
        "name": "Reconnaissance to Initial Breach",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "Attacker performs network reconnaissance.", "prob": 0.9, "summary_insight": "Attacker mapped the network."},
            
            # Question 1
            {"step": 2, "actor": "defender", "narration": "Firewall logs abnormal scan patterns.", "prob": 1.0, 
             "interactive": {
                 "question": "Port Scans detected from multiple IPs. Response?",
                 "options": [
                     {"id": "A", "label": "Log and Monitor only", "is_correct": False},
                     {"id": "B", "label": "Block IP Range immediately", "is_correct": True},
                     {"id": "C", "label": "Reset Firewall Rules", "is_correct": False},
                     {"id": "D", "label": "Ignore as noise", "is_correct": False}
                 ],
                 "feedback_correct": "Correct! Premptive blocking stopped the reconnaissance phase.",
                 "feedback_incorrect": "Mistake! Passive monitoring allowed the attacker to find open ports."
             }, "summary_insight": "Early detection was critical."},
            
            {"step": 3, "actor": "attacker", "target": "Firewall", "narration": "Attacker probes firewall rules.", "prob": 0.7, "summary_insight": "Attacker tested boundaries."},
            {"step": 4, "actor": "soc", "narration": "SOC detects early reconnaissance indicators.", "prob": 0.8, "summary_insight": "SOC team was alerted."},
            
             # Question 2
            {"step": 5, "actor": "defender", "narration": "Firewall applies temporary rate limiting.", "prob": 1.0,
             "interactive": {
                 "question": "Traffic spike detected on Port 80. Action?",
                 "options": [
                     {"id": "A", "label": "Shutdown Web Server", "is_correct": False},
                     {"id": "B", "label": "Enable Rate Limiting", "is_correct": True},
                     {"id": "C", "label": "Do Nothing", "is_correct": False},
                     {"id": "D", "label": "Block All Port 80 Traffic", "is_correct": False}
                 ],
                 "feedback_correct": "Good choice. Rate limiting mitigates the attack without causing downtime.",
                 "feedback_incorrect": "Incorrect. Shutting down causes self-inflicted DoS, creating panic."
             }, "summary_insight": "Traffic management is key to resilience."},

            {"step": 6, "actor": "attacker", "target": "Server", "narration": "Attacker attempts to bypass WAF.", "prob": 0.6, "summary_insight": "WAF Evasion attempted."},
            
            # Question 3
            {"step": 7, "actor": "defender", "narration": "WAF flags suspicious SQL patterns.", "prob": 1.0,
             "interactive": {
                 "question": "SQL Injection pattern observed in login form. Mitigation?",
                 "options": [
                     {"id": "A", "label": "Delete the Database", "is_correct": False},
                     {"id": "B", "label": "Update WAF Rules to Drop", "is_correct": True},
                     {"id": "C", "label": "Whitelist the IP", "is_correct": False},
                     {"id": "D", "label": "Disable Login Page", "is_correct": False}
                 ],
                 "feedback_correct": "Excellent. Blocking the payload at the WAF level prevents DB access.",
                 "feedback_incorrect": "Deleting the DB is catastrophic. WAF rules are the correct response."
             }, "summary_insight": "WAF tuning prevented data breach."},

            {"step": 8, "actor": "soc", "narration": "Incident response initiated.", "prob": 1.0, "summary_insight": "IR team deployed."}
        ]
    },

    # =========================================================
    # 2️⃣ Firewall Breach Attack (Interactive)
    # =========================================================
    2: {
        "id": 2,
        "name": "Firewall Breach Attack",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Firewall", "narration": "Attacker launches firewall attack.", "summary_insight": "Direct assault on perimeter."},
            
            # Question 1
            {"step": 2, "actor": "defender", "narration": "Firewall detects malformed packets.", 
             "interactive": {
                 "question": "Malformed packets hitting the firewall. Action?",
                 "options": [
                     {"id": "A", "label": "Allow for Analysis", "is_correct": False},
                     {"id": "B", "label": "Inspect Deep Payload", "is_correct": False},
                     {"id": "C", "label": "Drop Malformed Packets", "is_correct": True},
                     {"id": "D", "label": "Route to Honeypot", "is_correct": False}
                 ],
                 "feedback_correct": "Correct. Dropping invalid packets instantly protects the core.",
                 "feedback_incorrect": "Too slow! Deep inspection caused high CPU load, aiding the DoS."
             }, "summary_insight": "Packet filtering efficiency tested."},
             
            {"step": 3, "actor": "attacker", "target": "Firewall", "narration": "Attacker exploits outdated firmware component.", "summary_insight": "Firmware CVE exploited."},
            
             # Question 2
            {"step": 4, "actor": "defender", "narration": "Firewall firmware vulnerability flagged.",
             "interactive": {
                 "question": "Zero-day vulnerability reported in firewall firmware. Next step?",
                 "options": [
                     {"id": "A", "label": "Apply Hotfix Immediately", "is_correct": True},
                     {"id": "B", "label": "Wait for weekend patch", "is_correct": False},
                     {"id": "C", "label": "Replace hardware", "is_correct": False},
                     {"id": "D", "label": "Disable Firewall", "is_correct": False}
                 ],
                 "feedback_correct": "Critical patch applied successfully. Vulnerability closed.",
                 "feedback_incorrect": "Waiting allows the attacker time to exploit the hole."
             }, "summary_insight": "Patch management is critical."},
            
            {"step": 5, "actor": "attacker", "target": "Server", "narration": "Attacker attempts to bypass secondary controls.", "summary_insight": "Perimeter breached."},
            
            # Question 3
            {"step": 6, "actor": "defender", "narration": "Firewall reloads security rules.", 
             "interactive": {
                 "question": "Rules engine compromised. Restore strategy?",
                 "options": [
                     {"id": "A", "label": "Reload Last Known Good Config", "is_correct": True},
                     {"id": "B", "label": "Write New Rules Manually", "is_correct": False},
                     {"id": "C", "label": "Disable Firewall", "is_correct": False},
                     {"id": "D", "label": "Reboot Firewall", "is_correct": False}
                 ],
                 "feedback_correct": "Excellent. Restoring the backup config regained control quickest.",
                 "feedback_incorrect": "Manual writing is too slow during an active breach. Rebooting preserves the flaw."
             }, "summary_insight": "Configuration management saved the day."},

            {"step": 7, "actor": "soc", "narration": "Firewall breach contained.", "summary_insight": "Breach contained."}
        ]
    },

    # =========================================================
    # 3️⃣ Insider Data Exfiltration (Interactive)
    # =========================================================
    3: {
        "id": 3,
        "name": "Insider Data Exfiltration",
        "steps": [
            {"step": 1, "actor": "insider", "target": "Server", "narration": "Insider logs into internal server.", "summary_insight": "Legitimate credentials used."},
            
            # Question 1
            {"step": 2, "actor": "defender", "narration": "Firewall observes trusted access.", 
             "interactive": {
                 "question": "User accessing server at 2 AM. Flag as suspicious?",
                 "options": [
                     {"id": "A", "label": "Ignore (Authorized User)", "is_correct": False},
                     {"id": "B", "label": "Flag for Review (UEBA)", "is_correct": True},
                     {"id": "C", "label": "Block User Immediately", "is_correct": False},
                     {"id": "D", "label": "Call User", "is_correct": False}
                 ],
                 "feedback_correct": "Smart. Flagging behavior without blocking avoids false positives but alerts SOC.",
                 "feedback_incorrect": "Blocking an authorized user disrupts business without proof."
             }, "summary_insight": "Behavioral analytics were relevant."},

            {"step": 3, "actor": "insider", "target": "Database", "narration": "Insider accesses sensitive records.", "summary_insight": "Sensitive data accessed."},
            
             # Question 2
            {"step": 4, "actor": "soc", "narration": "SOC notices massive data download.", 
             "interactive": {
                 "question": "User downloading 50GB of HR data. Action?",
                 "options": [
                     {"id": "A", "label": "Allow (Work related)", "is_correct": False},
                     {"id": "B", "label": "Throttle Bandwidth", "is_correct": False},
                     {"id": "C", "label": "Trigger DLP Block", "is_correct": True},
                     {"id": "D", "label": "Encrypt Data", "is_correct": False}
                 ],
                 "feedback_correct": "DLP (Data Loss Prevention) rules successfully stopped the exfiltration.",
                 "feedback_incorrect": "Allowing the download results in a major data breach."
             }, "summary_insight": "DLP rules enforcement."},
            
            {"step": 5, "actor": "insider", "target": "Database", "narration": "Insider uses backup channel.", "summary_insight": "Data copy event."},
            {"step": 6, "actor": "attacker", "target": "Server", "narration": "External attacker coordinates with insider.", "summary_insight": "Collusion detected."},
            
            # Question 3
            {"step": 7, "actor": "defender", "narration": "Firewall blocks insider account.", 
             "interactive": {
                 "question": "Confident of malicious intent. Final Action?",
                 "options": [
                     {"id": "A", "label": "Email User for explanation", "is_correct": False},
                     {"id": "B", "label": "Revoke Credentials & Lock Account", "is_correct": True},
                     {"id": "C", "label": "Monitor for 24h", "is_correct": False},
                     {"id": "D", "label": "File Police Report", "is_correct": False}
                 ],
                 "feedback_correct": "Decisive action required. Revoking access stops the leak immediately.",
                 "feedback_incorrect": "Any delay gives the insider time to wipe tracks or finish theft."
             }, "summary_insight": "Identity management response was fast."},

            {"step": 8, "actor": "soc", "narration": "Data exfiltration prevented.", "summary_insight": "Exfiltration stopped."}
        ]
    },

    # =========================================================
    # 4️⃣ Privilege Escalation Attack (Interactive)
    # =========================================================
    4: {
        "id": 4,
        "name": "Privilege Escalation Attack",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "Attacker gains low-level access.", "summary_insight": "Initial foothold established."},
            
            # Question 1
            {"step": 2, "actor": "attacker", "target": "Server", "narration": "Attacker attempts sudo command.", 
             "interactive": {
                 "question": "Unexpected sudo usage detected. Validating...",
                 "options": [
                     {"id": "A", "label": "Allow (Admin activity)", "is_correct": False},
                     {"id": "B", "label": "Reboot Server", "is_correct": False},
                     {"id": "C", "label": "Challenge with MFA", "is_correct": True},
                     {"id": "D", "label": "Log event", "is_correct": False}
                 ],
                 "feedback_correct": "Correct. Stepping up authentication (MFA) stops stolen credential usage.",
                 "feedback_incorrect": "Allowing it gives away the keys to the kingdom."
             }, "summary_insight": "MFA challenge was the checkpoint."},

            {"step": 3, "actor": "soc", "narration": "SOC flags abnormal permission changes.", "summary_insight": "Permissions altered."},
            
             # Question 2
            {"step": 4, "actor": "attacker", "target": "Server", "narration": "Attacker tries Kernel exploit (Dirty Cow).",
             "interactive": {
                 "question": "Kernel exploit signature detected in memory. Reaction?",
                 "options": [
                     {"id": "A", "label": "Kill Process", "is_correct": False},
                     {"id": "B", "label": "Freeze Process & Dump Memory", "is_correct": True},
                     {"id": "C", "label": "Ignore (False Positive)", "is_correct": False},
                     {"id": "D", "label": "Restart Service", "is_correct": False}
                 ],
                 "feedback_correct": "Correct. Freezing preserves evidence and stops the exploit execution.",
                 "feedback_incorrect": "Killing it destroys forensic evidence. Freezing is preferred."
             }, "summary_insight": "Memory forensics triggered."},

            {"step": 5, "actor": "attacker", "target": "Firewall", "narration": "Attacker disables security controls.", "summary_insight": "Defenses weakened."},
            {"step": 6, "actor": "attacker", "target": "Database", "narration": "Attacker accesses restricted data.", "summary_insight": "Restricted data touched."},
            
            # Question 3
            {"step": 7, "actor": "soc", "narration": "SOC confirms root compromise.", 
             "interactive": {
                 "question": "Root compromise confirmed. Mitigation?",
                 "options": [
                     {"id": "A", "label": "Change Root Password", "is_correct": False},
                     {"id": "B", "label": "Isolate Host from Network", "is_correct": True},
                     {"id": "C", "label": "Run Antivirus Scan", "is_correct": False},
                     {"id": "D", "label": "Restore Files", "is_correct": False}
                 ],
                 "feedback_correct": "Correct. Isolation prevents the attacker from pivoting to other systems.",
                 "feedback_incorrect": "Changing password is useless if they have a shell. Isolation is priority."
             }, "summary_insight": "Containment was prioritized."},

            {"step": 8, "actor": "defender", "narration": "Admin access revoked.", "summary_insight": "Admins locked out."}
        ]
    },

    # =========================================================
    # 5️⃣ Lateral Movement Attack (Interactive)
    # =========================================================
    5: {
        "id": 5,
        "name": "Lateral Movement Attack",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "Attacker compromises one server.", "summary_insight": "Patient Zero compromised."},
            
            # Question 1
            {"step": 2, "actor": "defender", "narration": "Firewall logs east-west traffic.", 
             "interactive": {
                 "question": "Server A is scanning Server B. Intent?",
                 "options": [
                     {"id": "A", "label": "Block East-West Traffic", "is_correct": True},
                     {"id": "B", "label": "Allow (Internal Trust)", "is_correct": False},
                     {"id": "C", "label": "Log for Audit", "is_correct": False},
                     {"id": "D", "label": "Increase Bandwidth", "is_correct": False}
                 ],
                 "feedback_correct": "Correct. Zero Trust principles say we block suspicious internal traffic.",
                 "feedback_incorrect": "Assuming internal trust is how they spread. Bad move."
             }, "summary_insight": "Zero Trust segmentation enforced."},
            
            {"step": 3, "actor": "attacker", "target": "Firewall", "narration": "Attacker attempts RDP connection.", "summary_insight": "RDP attempted."},
            
             # Question 2
            {"step": 4, "actor": "soc", "narration": "RDP connection to critical asset detected.",
             "interactive": {
                 "question": "Why is RDP open on the DB Server?",
                 "options": [
                     {"id": "A", "label": "Close Port 3389", "is_correct": True},
                     {"id": "B", "label": "Monitor Session", "is_correct": False},
                     {"id": "C", "label": "Allow for Admin", "is_correct": False},
                     {"id": "D", "label": "Change port to 33890", "is_correct": False}
                 ],
                 "feedback_correct": "RDP should not be exposed. Closing the port removes the attack vector.",
                 "feedback_incorrect": "Monitoring RDP lets them in. Obscurity (changing ports) is not security."
             }, "summary_insight": "Attack Surface Reduction."},
            
            {"step": 5, "actor": "attacker", "target": "Database", "narration": "Attacker moves toward database.", "summary_insight": "Target acquired: Database."},
            {"step": 6, "actor": "attacker", "target": "Database", "narration": "Unauthorized database query executed.", "summary_insight": "SQL query ran."},
            
            # Question 3
            {"step": 7, "actor": "soc", "narration": "SOC raises lateral movement alert.", 
             "interactive": {
                 "question": "Attack spreading to DB. Emergency Action?",
                 "options": [
                     {"id": "A", "label": "Restart Switch", "is_correct": False},
                     {"id": "B", "label": "Quarantine Both Hosts", "is_correct": True},
                     {"id": "C", "label": "Alert CIO", "is_correct": False},
                     {"id": "D", "label": "Delete User Accounts", "is_correct": False}
                 ],
                 "feedback_correct": "Correct. Quarantining limits the blast radius effectively.",
                 "feedback_incorrect": "Restarting the switch disrupts the whole company. Overkill."
             }, "summary_insight": "Blast radius minimized."},

            {"step": 8, "actor": "soc", "narration": "Attack path neutralized.", "summary_insight": "Path covered."}
        ]
    },

    # =========================================================
    # 6️⃣ Ransomware Negotiation (Interactive) - MOVED FROM 11
    # =========================================================
    6: {
        "id": 6,
        "name": "Ransomware Negotiation",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "Attacker deploys ransomware payload."},
            
            # Question 1
            {"step": 2, "actor": "defender", "narration": "Files starting to become encrypted.",
             "interactive": {
                 "question": "High IOPS and entropy detected on file server. Action?",
                 "options": [
                     {"id": "A", "label": "Cut Network Connection", "is_correct": True},
                     {"id": "B", "label": "Scan for Virus", "is_correct": False},
                     {"id": "C", "label": "Backup Files Now", "is_correct": False},
                     {"id": "D", "label": "Shutdown Server", "is_correct": False}
                 ],
                 "feedback_correct": "Severing the network stops the spread to other shares immediately.",
                 "feedback_incorrect": "Backing up encrypted files is useless. Shutting down risks data corruption."
             }, "summary_insight": "Rapid containment."},

            {"step": 3, "actor": "attacker", "target": "Database", "narration": "Database files encrypted. Ransom note received.",
             # Question 2
             "interactive": {
                 "question": "Data Encrypted. $5M Ransom Demanded. Action?",
                 "options": [
                     {"id": "A", "label": "Pay Ransom immediately", "is_correct": False},
                     {"id": "B", "label": "Negotiate for lower price", "is_correct": False},
                     {"id": "C", "label": "Activate Offline Backups", "is_correct": True},
                     {"id": "D", "label": "Ignore Ransom", "is_correct": False}
                 ],
                 "feedback_correct": "Perfect. Offline backups are immune to online ransomware. Restoration begun.",
                 "feedback_incorrect": "Paying funds criminal activity and guarantees nothing."
             }, "summary_insight": "Backups saved the company."},
            
            {"step": 4, "actor": "attacker", "narration": "Attacker threatens data leak."},
            
            # Question 3
            {"step": 5, "actor": "soc", "narration": "Double extortion confirmed.",
             "interactive": {
                 "question": "Attacker claims they have data. How to verify?",
                 "options": [
                     {"id": "A", "label": "Pay to prevent leak", "is_correct": False},
                     {"id": "B", "label": "Check Exfiltration Logs", "is_correct": True},
                     {"id": "C", "label": "Ask Attacker for proof", "is_correct": False},
                     {"id": "D", "label": "Trust them", "is_correct": False}
                 ],
                 "feedback_correct": "Verification is key. Logs showed NO data left the network.",
                 "feedback_incorrect": "Never trust the attacker. Data proves the lie."
             }, "summary_insight": "Log analysis disproved the threat."},

            {"step": 6, "actor": "defender", "narration": "Systems restored from gold image."},
            {"step": 7, "actor": "soc", "narration": "Business operations resumed."}
        ]
    },

    # =========================================================
    # 7️⃣ Supply Chain Compromise (Interactive) - MOVED FROM 12
    # =========================================================
    7: {
        "id": 7,
        "name": "Supply Chain Compromise",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "Malicious update pushed from trusted vendor."},
            
            # Question 1
            {"step": 2, "actor": "defender", "narration": "Update is digitally signed.",
             "interactive": {
                 "question": "Signed update from vendor requesting high privileges. Install?",
                 "options": [
                     {"id": "A", "label": "Install (Trusted)", "is_correct": False},
                     {"id": "B", "label": "Test in Sandbox first", "is_correct": True},
                     {"id": "C", "label": "Decline Update", "is_correct": False},
                     {"id": "D", "label": "Install on one server", "is_correct": False}
                 ],
                 "feedback_correct": "Correct. Always sandbox updates, even from trusted vendors.",
                 "feedback_incorrect": "Blind trust leads to compromise. Verification is necessary."
             }, "summary_insight": "Sandboxing prevented mass infection."},

            {"step": 3, "actor": "attacker", "target": "Server", "narration": "Backdoor activated via update.",
             # Question 2
             "interactive": {
                 "question": "Sandbox analysis shows beaconing to unknown IP. Action?",
                 "options": [
                     {"id": "A", "label": "Block Vendor Update Server", "is_correct": True},
                     {"id": "B", "label": "Allow (Signed binary)", "is_correct": False},
                     {"id": "C", "label": "Wait for official statement", "is_correct": False},
                     {"id": "D", "label": "Email Vendor", "is_correct": False}
                 ],
                 "feedback_correct": "Correct. Blocking the source stops the bleeding.",
                 "feedback_incorrect": "Waiting allows the malware to spread."
             }, "summary_insight": "Vendor trust was the vector."},
            
            {"step": 4, "actor": "soc", "narration": "SOC identifies beaconing malware."},
            {"step": 5, "actor": "attacker", "target": "Database", "narration": "Attacker loses connection to backdoor."},
            
            # Question 3
            {"step": 6, "actor": "soc", "narration": "Incident reported to vendor.",
             "interactive": {
                 "question": "Vendor confirms breach. Next Remediation Step?",
                 "options": [
                     {"id": "A", "label": "Uninstall Software", "is_correct": False},
                     {"id": "B", "label": "Hunt for IOCs in network", "is_correct": True},
                     {"id": "C", "label": "Demand Refund", "is_correct": False},
                     {"id": "D", "label": "Ignore", "is_correct": False}
                 ],
                 "feedback_correct": "Proactive hunting finds hidden backdoors they might have left.",
                 "feedback_incorrect": "Simply uninstalling doesn't remove the persistence hooks."
             }, "summary_insight": "Threat hunting cleared the network."},

            {"step": 7, "actor": "soc", "narration": "Supply chain attack neutralized."}
        ]
    },

    # =========================================================
    # 8️⃣ Cloud Bucket Leak (Interactive) - MOVED FROM 13
    # =========================================================
    8: {
        "id": 8,
        "name": "Cloud Bucket Leak",
        "steps": [
            {"step": 1, "actor": "insider", "target": "Database", "narration": "Developer misconfigures cloud storage permission."},
            
            # Question 1
            {"step": 2, "actor": "attacker", "target": "Database", "narration": "Attacker discovers public S3 bucket.",
             "interactive": {
                 "question": "Cloud Security Posture Management detected public bucket. Priority?",
                 "options": [
                     {"id": "A", "label": "Check Content Sensitivity", "is_correct": False},
                     {"id": "B", "label": "Auto-Remediate (Make Private)", "is_correct": True},
                     {"id": "C", "label": "Alert Developer", "is_correct": False},
                     {"id": "D", "label": "Log Event", "is_correct": False}
                 ],
                 "feedback_correct": "Immediate remediation is key. Fix it first, ask questions later.",
                 "feedback_incorrect": "Checking takes time. The data is leaking NOW."
             }, "summary_insight": "Auto-remediation saved data."},

            {"step": 3, "actor": "attacker", "narration": "Attacker begins downloading PII data.",
             # Question 2
             "interactive": {
                 "question": "Public access confirmed. Remediate?",
                 "options": [
                     {"id": "A", "label": "Monitor downloads", "is_correct": False},
                     {"id": "B", "label": "Enforce Private Access", "is_correct": True},
                     {"id": "C", "label": "Delete Bucket", "is_correct": False},
                     {"id": "D", "label": "Change Bucket Name", "is_correct": False}
                 ],
                 "feedback_correct": "Immediate remediation. Making it private stops the leak instantly.",
                 "feedback_incorrect": "Monitoring implies watching the data fly out the door."
             }, "summary_insight": "Misconfiguration was the root cause."},
            
            {"step": 4, "actor": "soc", "narration": "SOC audits cloud logs."},
            
            # Question 3
            {"step": 5, "actor": "defender", "narration": "IAM policies tightened.",
             "interactive": {
                 "question": "Developer permission was too broad. Fix?",
                 "options": [
                     {"id": "A", "label": "Revoke All Access", "is_correct": False},
                     {"id": "B", "label": "Implement Least Privilege", "is_correct": True},
                     {"id": "C", "label": "Trust Developer", "is_correct": False},
                     {"id": "D", "label": "Two-Person Rule", "is_correct": False}
                 ],
                 "feedback_correct": "Least Privilege ensures this mistake cannot happen again.",
                 "feedback_incorrect": "Revoking all access stops work. Least privilege balances security/productivity."
             }, "summary_insight": "IAM policy hardened."},

            {"step": 6, "actor": "soc", "narration": "Data leak contained."}
        ]
    },

    # =========================================================
    # 9️⃣ Social Engineering / Phishing (Interactive) - MOVED FROM 14
    # =========================================================
    9: {
        "id": 9,
        "name": "Social Engineering Phishing",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "Attacker sends targeted spear-phishing email."},
            
            # Question 1
            {"step": 2, "actor": "defender", "narration": "Email contains suspicious link.", 
             "interactive": {
                 "question": "Email link domain looks slightly off. Action?",
                 "options": [
                     {"id": "A", "label": "Click to verify", "is_correct": False},
                     {"id": "B", "label": "Sandbox URL Analysis", "is_correct": True},
                     {"id": "C", "label": "Delete Email", "is_correct": False},
                     {"id": "D", "label": "Reply to sender", "is_correct": False}
                 ],
                 "feedback_correct": "Safe analysis revealed the credential harvester.",
                 "feedback_incorrect": "Never click. Deleting it leaves others vulnerable."
             }, "summary_insight": "Email security gateway test."},

            {"step": 3, "actor": "insider", "target": "Server", "narration": "One employee clicks malicious link.",
             # Question 2
             "interactive": {
                 "question": "User credentials compromised. Immediate step?",
                 "options": [
                     {"id": "A", "label": "Block Email Domain", "is_correct": False},
                     {"id": "B", "label": "Fire Employee", "is_correct": False},
                     {"id": "C", "label": "Reset Password & MFA", "is_correct": True},
                     {"id": "D", "label": "Monitor Login", "is_correct": False}
                 ],
                 "feedback_correct": "Correct. Revoking access is priority #1.",
                 "feedback_incorrect": "Blocking the domain is too late; they have the keys."
             }, "summary_insight": "Human element was the weak link."},
            
            {"step": 4, "actor": "soc", "narration": "SOC detects impossible travel login."},
            
            # Question 3
            {"step": 5, "actor": "defender", "narration": "Session tokens invalidated.",
             "interactive": {
                 "question": "Multiple successful logins from Russia. Action?",
                 "options": [
                     {"id": "A", "label": "Geo-Block IP Range", "is_correct": False},
                     {"id": "B", "label": "Kill Sessions Globally", "is_correct": True},
                     {"id": "C", "label": "Ask User if traveling", "is_correct": False},
                     {"id": "D", "label": "Log as Warning", "is_correct": False}
                 ],
                 "feedback_correct": "Killing sessions forces everyone to re-authenticate with new creds.",
                 "feedback_incorrect": "They are already in. Geo-blocking won't stop established sessions."
             }, "summary_insight": "Session management saves the day."},

            {"step": 6, "actor": "soc", "narration": "Identity secured."}
        ]
    },

    # =========================================================
    # 🔟 IoT Botnet Takeover (Interactive) - MOVED FROM 15
    # =========================================================
    10: {
        "id": 10,
        "name": "IoT Botnet Takeover",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "Attacker scans for default IoT credentials."},
            
            # Question 1
            {"step": 2, "actor": "attacker", "target": "Firewall", "narration": "Smart cameras compromised.",
             "interactive": {
                 "question": "New IoT devices found with default passwords. Action?",
                 "options": [
                     {"id": "A", "label": "Leave as is", "is_correct": False},
                     {"id": "B", "label": "Change Passwords", "is_correct": False},
                     {"id": "C", "label": "Enforce MAC Filtering", "is_correct": False},
                     {"id": "D", "label": "Isolate in VLAN", "is_correct": True}
                 ],
                 "feedback_correct": "Best practice. IoT is insecure; keep it off the production network.",
                 "feedback_incorrect": "Passwords help, but segmentation is the only architectural fix."
             }, "summary_insight": "IoT Segmentation."},

            {"step": 3, "actor": "attacker", "narration": "Botnet launched from internal network.",
             # Question 2
             "interactive": {
                 "question": "Internal IoT devices attacking server. Mitigation?",
                 "options": [
                     {"id": "A", "label": "Segregate IoT VLAN", "is_correct": True},
                     {"id": "B", "label": "Scan for Viruses", "is_correct": False},
                     {"id": "C", "label": "Unplug everything", "is_correct": False},
                     {"id": "D", "label": "Restart Server", "is_correct": False}
                 ],
                 "feedback_correct": "Correct. IoT devices should never be on the main corporate network.",
                 "feedback_incorrect": "Scanning won't stop the traffic flood fast enough."
             }, "summary_insight": "Network segmentation is critical for IoT."},
            
            {"step": 4, "actor": "soc", "narration": "SOC isolates IoT subnet."},
            
            # Question 3
            {"step": 5, "actor": "attacker", "narration": "Botnet command & control link severed.",
             "interactive": {
                 "question": "Devices still trying to call home. Permanent Fix?",
                 "options": [
                     {"id": "A", "label": "Throw them away", "is_correct": False},
                     {"id": "B", "label": "Firmware Update & Hardening", "is_correct": True},
                     {"id": "C", "label": "Hide SSID", "is_correct": False},
                     {"id": "D", "label": "Disable Internet", "is_correct": False}
                 ],
                 "feedback_correct": "Updating firmware removes the vulnerability the botnet used.",
                 "feedback_incorrect": "Hiding SSID does nothing. Patching is the only fix."
             }, "summary_insight": "Vulnerability management."},

            {"step": 6, "actor": "soc", "narration": "Botnet eliminated."}
        ]
    },
    
    # =========================================================
    # 1️⃣1️⃣ Database Breach (Passive) - MOVED FROM 6
    # =========================================================
    11: {
        "id": 11,
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
    # 1️⃣2️⃣ DDoS Attack (Passive) - MOVED FROM 7
    # =========================================================
    12: {
        "id": 12,
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
    # 1️⃣3️⃣ SOC Incident Response (Passive) - MOVED FROM 8
    # =========================================================
    13: {
        "id": 13,
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
    # 1️⃣4️⃣ Zero-Day Exploit (Passive) - MOVED FROM 9
    # =========================================================
    14: {
        "id": 14,
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
    # 1️⃣5️⃣ Coordinated Multi-Agent Attack (Passive) - MOVED FROM 10
    # =========================================================
    15: {
        "id": 15,
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
    },

    # =========================================================
    # 1️⃣6️⃣ Cryptojacking (Passive)
    # =========================================================
    16: {
        "id": 16,
        "name": "Cryptojacking Attack",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "Attacker injects mining script into web server."},
            {"step": 2, "actor": "defender", "narration": "CPU usage spikes to 100%."},
            {"step": 3, "actor": "soc", "narration": "SOC investigates performance degradation."},
            {"step": 4, "actor": "soc", "narration": "Miner process identified."},
            {"step": 5, "actor": "defender", "narration": "Process terminated."},
            {"step": 6, "actor": "attacker", "target": "Server", "narration": "Script attempts restart."},
            {"step": 7, "actor": "defender", "narration": "File integrity monitoring triggers."},
            {"step": 8, "actor": "soc", "narration": "Malicious code removed."},
            {"step": 9, "actor": "defender", "narration": "Server patched."},
            {"step": 10, "actor": "soc", "narration": "Resources normalized."}
        ]
    },

    # =========================================================
    # 1️⃣7️⃣ Man-in-the-Middle (Wi-Fi) (Passive)
    # =========================================================
    17: {
        "id": 17,
        "name": "Wi-Fi Man-in-the-Middle",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "Attacker sets up rogue Wi-Fi AP."},
            {"step": 2, "actor": "insider", "target": "Server", "narration": "Employee connects to 'Free Corp WiFi'."},
            {"step": 3, "actor": "attacker", "narration": "Attacker intercepts session cookies."},
            {"step": 4, "actor": "soc", "narration": "SOC detects logins from unknown IP."},
            {"step": 5, "actor": "defender", "narration": "Session revocation triggered."},
            {"step": 6, "actor": "attacker", "narration": "Decryption fails due to HSTS."},
            {"step": 7, "actor": "soc", "narration": "Rogue AP located via signal triangulation."},
            {"step": 8, "actor": "defender", "narration": "WIPS (Wireless IPS) blocks AP."},
            {"step": 9, "actor": "soc", "narration": "Employee warned."},
            {"step": 10, "actor": "soc", "narration": "Wireless perimeter secured."}
        ]
    },

    # =========================================================
    # 1️⃣8️⃣ API Logic Flaw (Passive)
    # =========================================================
    18: {
        "id": 18,
        "name": "API Logic Flaw",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Database", "narration": "Attacker manipulates API ID parameter."},
            {"step": 2, "actor": "defender", "narration": "WAF sees legitimate-looking traffic."},
            {"step": 3, "actor": "attacker", "narration": "Attacker accesses other user's data (IDOR)."},
            {"step": 4, "actor": "soc", "narration": "SOC notices high volume data access."},
            {"step": 5, "actor": "defender", "narration": "API rate limit reached."},
            {"step": 6, "actor": "soc", "narration": "Authorization logs reviewed."},
            {"step": 7, "actor": "defender", "narration": "API endpoint disabled temporarily."},
            {"step": 8, "actor": "insider", "narration": "Dev team fixes authorization logic."},
            {"step": 9, "actor": "soc", "narration": "API service restored."},
            {"step": 10, "actor": "soc", "narration": "Logic flaw resolved."}
        ]
    },

    # =========================================================
    # 1️⃣9️⃣ CI/CD Pipeline Poisoning (Passive)
    # =========================================================
    19: {
        "id": 19,
        "name": "CI/CD Pipeline Poisoning",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Server", "narration": "Attacker gains access to Jenkins/GitLab."},
            {"step": 2, "actor": "attacker", "narration": "Malicious build step injected."},
            {"step": 3, "actor": "defender", "narration": "Build completes successfully."},
            {"step": 4, "actor": "soc", "narration": "Runtime anomaly in production."},
            {"step": 5, "actor": "soc", "narration": "Reverse engineering reveals injected code."},
            {"step": 6, "actor": "defender", "narration": "Pipeline halted."},
            {"step": 7, "actor": "attacker", "target": "Database", "narration": "Attacker attempts to wipe logs."},
            {"step": 8, "actor": "defender", "narration": "Immutable audit logs preserved."},
            {"step": 9, "actor": "soc", "narration": "Pipeline secrets rotated."},
            {"step": 10, "actor": "soc", "narration": "Clean build deployed."}
        ]
    },

    # =========================================================
    # 2️⃣0️⃣ Quantum Decryption Attack (Passive)
    # =========================================================
    20: {
        "id": 20,
        "name": "Quantum Decryption Attack",
        "steps": [
            {"step": 1, "actor": "attacker", "target": "Firewall", "narration": "Attacker captures encrypted traffic."},
            {"step": 2, "actor": "attacker", "narration": "Quantum computer breaks RSA keys."},
            {"step": 3, "actor": "defender", "narration": "Decryption detected by entropy monitor."},
            {"step": 4, "actor": "soc", "narration": "Keys compromised alert."},
            {"step": 5, "actor": "defender", "narration": "Switching to Post-Quantum Cryptography (PQC)."},
            {"step": 6, "actor": "attacker", "target": "Database", "narration": "Attacker loses visibility."},
            {"step": 7, "actor": "soc", "narration": "Session keys renegotiated."},
            {"step": 8, "actor": "defender", "narration": "Legacy ciphers disabled."},
            {"step": 9, "actor": "soc", "narration": "Quantum resistance confirmed."},
            {"step": 10, "actor": "soc", "narration": "Future-proof defense active."}
        ]
    }
}
