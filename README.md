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

📥 [Download Full Report (PDF)](https://drive.google.com/file/d/1n9JM2sLnqkehX-quGWLABdFBOguQqAeV/view?usp=sharing)

---

## 📕 Project Introduction
SoCraTech has been experiencing abnormal network activities, possible breaches, malware infection, and internal cybersecurity threats. I was brought in as a SOC analyst in order to implement a proactive defense strategy. Part of my responsibilities included deploying monitoring systems, analyzing security events in real-time through traffic capturing, identifying vulnerabilities and responding to events. In this report, I detail the methods employed, the findings and impact, resolutions and recommendations.

## Methodology 
The engagement followed a structured multi-phase approach:
• Wireshark was used for packet capture and protocol analysis. 
• pfSense was configured to implement firewall and IDS/IPS rules. 
• Wazuh served as a centralized SIEM for alerting, log correlation, and response.

## 🔎 Key Phases

### 📡 Phase 1: Wireshark – Network Traffic Capture & Analysis 
- Objective: Capture and analyze SoCraTech’s network traffic for suspicious activities.
- Key Actions: 
  - Focused on HTTP, DNS, SSH traffic 
  - Identified suspicious DNS queries and unusual HTTP patterns 
- Tools: Wireshark and Kali 
- Findings: Potential malware beaconing; unauthorized data exfiltration attempts; brute force attack
- Artifacts: Screenshots and mini-report attached in Appendix A.

### 🔥 Phase 2: pfSense – Firewall & Policy Enforcement 
- Objective: Detect and block malicious traffic using firewall rules and IPS
- Key Actions: 
  - Configured Snort IDS, GeoIP filtering
  - Set up firewall rules to block malicious IP addresses
  - Monitored and blocked brute force attempts
- Tools: pfSense; Snort (IPS/IDS)
- Findings: Blocked multiple unauthorized SSH attempts and malicious IPs
- Artifacts: Screenshots and mini-report attached in Appendix B

### 🧭 Phase 3: Wazuh  – Security Event Monitoring & Response
- Objective: Correlate logs and respond to security incidents 
- Key Actions:
  - Configured log forwarding from endpoints 
  - Detected privilege escalation attack and suspicious user behavior
- Tools: Wazuh SIEM 
- Findings: Multiple alerts correlated with anomalies identified in Wireshark
- Artifacts: Screenshots and mini-report attached in Appendix C

---

## 🚨 Final Findings & IRP Summary

### Incident Response Plan (IRP)
- Preparation: The security & monitoring tools were deployed for network monitoring and intrusion detection, tasks of the SOC team were defined and ensured that logs were centralized and retained for analysis.
- Identification: Indicators of Compromise were noticed as unusual traffic patterns, unauthorized login attempts from external IPs, alerts triggered by Wazuh indicating malware activity.
- Containment: In order to limit the spread and impact of the incident, affected systems were isolated from the network, suspicious IP addresses and domains were blocked by setting pfSense firewall rules.
- Eradication: Malware infected files were removed and suspicious processes terminated.
- Recovery: Reconnected cleaned systems to the network in a controlled environment, closely monitored systems post-recovery and verified all systems were functioning properly.
- Lessons Learned: Learned from the malicious attacks and weakness identified, recommended the implementation of core security measures to prevent the events identified from recurring in the future.

### Security Risks
The engagement confirmed that SoCraTech was susceptible to the following risks:

- Data theft, ransomware deployment, and loss of system control.
- Intellectual property loss, regulatory violations (e.g., GDPR, HIPAA), and reputational damage.
- Compromised credentials, especially for critical infrastructure or privileged accounts.
- Total system compromise, unauthorized access to sensitive files, lateral movement across the network.
- Malware or threat actors could operate undetected for extended periods
- Possible exposure to state-sponsored or organized cybercrime activity.

---

## ✅ Recommendations

Based on findings, the following are recommended: 
- The implementation of Multi-Factor Authentication (MFA) for all employees for remote access, as well as internally for privileged accounts and sensitive systems. This adds an extra layer of protection, even if passwords are compromised.
- Invest in tools that monitor employee accounts and company devices for unusual behavior. This helps detect threats early like unauthorized access or data theft.
- Put systems in place that track and prevent unauthorized sharing or sending of data outside the company. This reduces the risk of accidental or malicious data leaks.
- Separate critical systems (like HR, Finance, and servers) from general employee access. If a breach happens, this limits how far it can spread.
- Regularly update systems to block known malicious websites, IP addresses, attack patterns and close known security holes. This prevents attackers from even reaching the network. Many attacks take advantage of vulnerabilities like outdated software.
- Provide ongoing cybersecurity awareness training. Employees are the first line of defense and need to stay informed.
- Ensure scheduled regular audits, updated incident response documentation and refined incident detection plan.

---

## ✍️ Conclusion

SoCraTech's SOC analysis showed vulnerabilities like malware attack, unauthorized access, and possible data breaches. While threats were mitigated through traffic monitoring, firewall configurations, and log reviews, recommendations were given to enhance the organization's security strategy. Adopting the recommendations provided will enhance the company's security posture and prevent incidents from occurring in the future.

## 🧾 References

- [Wireshark Documentation](https://www.wireshark.org/docs/)  
- [pfSense IDS/IPS Guide](https://docs.netgate.com/pfsense/en/latest/)  
- [Wazuh Documentation](https://documentation.wazuh.com/)  
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Threat intelligence references](https://rules.emergingthreats.net/)
- Logs and dashboards from the lab environment: Pls see screenshots in Appendices
- Raw logs, alert data, and full packet captures: Pls see screenshots in Appendices
- IOC lists: Brute Force attack, SSH login attempts, malware, C2 server communications.

## See Appendices for:
- Appendix A: Wireshark Findings  
- Appendix B: pfSense Analysis  
- Appendix C: Wazuh Logs
- Screenshots  
- Raw logs  
- IOC lists  
- Snort alerts
### 📥 [Download Appendices in the full report (PDF)](https://drive.google.com/file/d/1n9JM2sLnqkehX-quGWLABdFBOguQqAeV/view?usp=sharing)

