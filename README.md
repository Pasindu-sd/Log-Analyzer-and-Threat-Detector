# Log-Analyzer-and-Threat-Detector

A simple **Python tool** that reads system/auth logs and detects **suspicious patterns** such as brute-force login attempts, failed SSH logins, and other anomalies.

---

## Features
- Parses system/auth logs for suspicious IPs  
- Counts failed login attempts  
- Generates a clean security report  
- Highlights IPs over a defined threshold  

---

## Add a Sample Code here
Sample Output
```
=== Security Report ===
IP: 192.168.1.105 - Failed attempts: 8
IP: 103.21.244.15 - Failed attempts: 5
IP: 91.189.88.181 - Failed attempts: 3
IP: 185.234.218.32 - Failed attempts: 2
IP: 72.165.87.91 - Failed attempts: 1

Suspicious IPs (Over Threshold):
192.168.1.105 - 8 failed attempts
103.21.244.15 - 5 failed attempts
91.189.88.181 - 3 failed attempts

Report saved to: security_report.txt

```

---

```
     ⚠️ UNDER DEVELOPMENT ⚠️
```

---
