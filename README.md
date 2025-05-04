# SOC-Analysis

# 🛡️ Threat Detection & Incident Response Using Wireshark, pfSense, and Wazuh

Welcome to my final project for SoCra Tech, where I took on the role of a SOC Analyst to detect, respond to, and contain cyber threats using open-source tools in a lab simulation.

---

## 📄 Project Summary

🔍 **Objective:** Investigate suspicious activity on SoCraTech’s network using traffic analysis, firewall policies, and SIEM monitoring.

🧠 **Tools Used:**  
- Wireshark (traffic capture & analysis)  
- pfSense (firewall configuration, Snort IDS/IPS)  
- Wazuh (SIEM - log correlation, alerting, response)  

👤 **Role:** Security Operations Center (SOC) Analyst  
📅 **Submission Date:** April 24, 2025  
🏢 **Organization:** SoCra Tech  
🧾 **Analyst:** Tega Olomu

---

## 📚 Contents

1. [Executive Summary](#executive-summary)
2. [Project Introduction](#project-introduction)
3. [Methodology](#methodology)
4. [Phase-by-Phase Analysis](#phase-by-phase-analysis)
5. [Final Findings & Impact](#final-findings--impact)
6. [Recommendations](#recommendations)
7. [Conclusion](#conclusion)
8. [References](#references)
9. [Appendices](#appendices)

---

## 🧠 Executive Summary

A multi-phase threat analysis was conducted using Wireshark, pfSense, and Wazuh. Suspicious traffic, unauthorized access, and malware behavior were identified. Actions were taken to block malicious IPs and implement firewall policies. A full report with insights and practical recommendations is included below.

---

## 📌 Report Download

📥 [Download Full Report (PDF)](./Report/Final_Incident_Report_Tega_Olomu.pdf)

---

## 🔎 Key Phases

### 📡 Phase 1: Wireshark  
- Captured and analyzed DNS, HTTP, SSH traffic  
- Identified brute force attacks, malware beaconing  
- [Appendix A](./Report/Appendix_A_Wireshark_Analysis.pdf)

### 🔥 Phase 2: pfSense  
- Set up IDS (Snort), firewall rules, GeoIP filtering  
- Blocked malicious IPs (C2 servers, Phobos ransomware)  
- [Appendix B](./Report/Appendix_B_pfSense_Analysis.pdf)

### 🧭 Phase 3: Wazuh  
- Configured endpoint monitoring, triggered incident alerts  
- Detected password guessing, lateral movement  
- [Appendix C](./Report/Appendix_C_Wazuh_Analysis.pdf)

---

## 🚨 Final Findings & Impact

- Detected brute force and privilege escalation attempts  
- Identified infected systems communicating with C2 servers  
- Implemented containment and eradication via firewall & host isolation  
- Logs showed threat actor activity across multiple phases  
- Read [Final Findings & IRP Summary](./Report/Final_Incident_Report_Tega_Olomu.pdf#page=12)

---

## ✅ Recommendations

- Enforce MFA for all users  
- Implement behavioral monitoring tools  
- Restrict data sharing privileges  
- Segment critical infrastructure from general access  
- Patch systems regularly  
- Train staff continuously on cyber hygiene  
- Regular audits & IR plan reviews

---

## 🧾 References

- [Wireshark Documentation](https://www.wireshark.org/docs/)  
- [pfSense IDS/IPS Guide](https://docs.netgate.com/pfsense/en/latest/)  
- [Wazuh Documentation](https://documentation.wazuh.com/)  
- [MITRE ATT&CK](https://attack.mitre.org/)  
- [Emerging Threats Rules](https://)
