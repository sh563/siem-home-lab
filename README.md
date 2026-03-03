# 🔐 SIEM Home Lab — Threat Detection with Splunk & Sysmon

![Status](https://img.shields.io/badge/Status-In%20Progress-yellow)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-black)
![OS](https://img.shields.io/badge/OS-Windows%2011%20%2B%20Ubuntu%2022.04-blue)
![Lab](https://img.shields.io/badge/Lab-VirtualBox-orange)
![License](https://img.shields.io/badge/License-MIT-green)

> A hands-on home lab simulating a real SOC environment — ingesting Windows and Sysmon logs into Splunk, detecting live attacks, and building analyst dashboards.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Tools & Technologies](#tools--technologies)
- [Lab Setup](#lab-setup)
- [Detections Built](#detections-built)
- [Dashboard](#dashboard)
- [Attack Simulations](#attack-simulations)
- [Key Findings](#key-findings)
- [Screenshots](#screenshots)
- [How to Reproduce](#how-to-reproduce)
- [Lessons Learned](#lessons-learned)
- [Next Steps](#next-steps)

---

## Overview

This project builds a functional two-VM SIEM lab to detect real attack patterns including brute force logins, port scanning, and credential dumping attempts. Windows Event Logs and Sysmon telemetry are forwarded into Splunk Enterprise where custom SPL detection rules fire alerts and a live SOC dashboard tracks activity.

**Key goals:**
- Forward and parse Windows security logs into a SIEM
- Write detection logic for common attack patterns (MITRE ATT&CK aligned)
- Build a real-time SOC analyst dashboard
- Document findings the way a real analyst would

---

## Architecture

```
┌─────────────────────────┐        logs (port 9997)       ┌─────────────────────────┐
│   VM 1 — Windows 11     │ ─────────────────────────────► │   VM 2 — Ubuntu 22.04   │
│   IP: 192.168.56.10     │                                │   IP: 192.168.56.20     │
│                         │                                │                         │
│  • Sysmon + config      │                                │  • Splunk Enterprise    │
│  • Splunk UF agent      │                                │  • Detection rules      │
│  • Attack target        │                                │  • SOC Dashboard        │
└─────────────────────────┘                                └─────────────────────────┘
          ▲                                                           │
          │                  Host-Only Network                        │
          │              (VirtualBox vboxnet0)                        │
          └────────────── Attacker: nmap scans ◄─────────────────────┘
```

**Network:** VirtualBox Host-Only Adapter — 192.168.56.0/24  
**Host Machine:** [Your OS + RAM here, e.g. Windows 11, 32GB RAM]

---

## Tools & Technologies

| Category | Tool | Purpose |
|----------|------|---------|
| SIEM | Splunk Enterprise (Free) | Log ingestion, detection, dashboards |
| Endpoint Logging | Microsoft Sysmon | Deep Windows telemetry |
| Sysmon Config | SwiftOnSecurity ruleset | Best-practice event filtering |
| Log Forwarder | Splunk Universal Forwarder | Ship Windows logs to Splunk |
| Virtualization | VirtualBox 7.x | Host both VMs |
| Attack Simulation | nmap, PowerShell | Port scan, brute force simulation |
| OS — Target | Windows 11 | Log source and attack target |
| OS — SIEM | Ubuntu 22.04 LTS | Splunk server host |

---

## Lab Setup

### Prerequisites
- VirtualBox 7.x installed on host
- Windows 11 ISO
- Ubuntu 22.04 LTS ISO
- Free Splunk account (splunk.com)
- Minimum 16GB RAM on host machine

### Phase 1 — VirtualBox Network
```bash
# Host-Only Network settings:
# IP: 192.168.56.1
# Subnet: 255.255.255.0
# DHCP: Disabled
```

### Phase 2 — Sysmon Installation (Windows VM)
```powershell
# Download and install Sysmon with SwiftOnSecurity config
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile C:\Sysmon.zip
Expand-Archive C:\Sysmon.zip -DestinationPath C:\Sysmon
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' -OutFile C:\Sysmon\sysmonconfig.xml
cd C:\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

### Phase 3 — Splunk Server (Ubuntu VM)
```bash
sudo dpkg -i splunk-9.x.x-linux-amd64.deb
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start
sudo ufw allow 8000
sudo ufw allow 9997
```
Access Splunk UI: `http://192.168.56.20:8000`

### Phase 4 — Splunk Universal Forwarder (Windows VM)
```powershell
cd 'C:\Program Files\SplunkUniversalForwarder\bin'
.\splunk add monitor 'C:\Windows\System32\winevt\Logs\Security.evtx'
.\splunk add monitor 'C:\Windows\System32\winevt\Logs\System.evtx'
.\splunk add monitor 'C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx'
.\splunk restart
```

Full step-by-step setup guide: [`/docs/setup-guide.md`](docs/setup-guide.md)

---

## Detections Built

| # | Attack Technique | MITRE ATT&CK | Event IDs | Detection Logic |
|---|-----------------|--------------|-----------|-----------------|
| 1 | Brute Force Login | T1110.001 | 4625 | >5 failed logins / 5 min, same source |
| 2 | Port Scanning | T1046 | 5156, 5157 | >20 connection attempts from single IP |
| 3 | LSASS Memory Access | T1003.001 | Sysmon 10 | Process accessing lsass.exe memory |
| 4 | New User Account Created | T1136.001 | 4720 | Any new local account creation |
| 5 | Privilege Escalation Attempt | T1548 | 4672 | Special privileges assigned at logon |

### Sample Detection — Brute Force (SPL)
```spl
index=* sourcetype=WinEventLog EventCode=4625
| stats count by src_ip, user
| where count > 5
| sort -count
```

### Sample Detection — LSASS Access (SPL)
```spl
index=* source=*Sysmon* EventCode=10 TargetImage=*lsass*
| table _time, SourceImage, TargetImage, GrantedAccess
| sort -_time
```

All detection queries: [`/detections/`](detections/)

---

## Dashboard

Built a 4-panel SOC dashboard in Splunk tracking:

- **Failed Logins Over Time** — timechart of Event ID 4625 by user
- **Top Source IPs** — bar chart of most active source IPs
- **Sysmon Process Activity** — top processes by execution count
- **Alert Summary by Type** — pie chart breakdown of alert categories

> 📸 Screenshot: [`/screenshots/splunk-dashboard.png`](screenshots/splunk-dashboard.png)
> *(Add your dashboard screenshot here once built)*

---

## Attack Simulations

### Simulation 1 — Brute Force Login
```powershell
# Generate 10 failed login attempts against a fake account
1..10 | ForEach-Object {
    net user fakeadmin wrongpassword 2>$null
    Start-Sleep -Milliseconds 500
}
```
**Result:** Splunk fired alert after 5th failed attempt. Event ID 4625 logged for each failure.  
**Screenshot:** [`/screenshots/brute-force-alert.png`](screenshots/brute-force-alert.png)

---

### Simulation 2 — Port Scan
```bash
# Run nmap scan from Ubuntu against Windows VM
nmap -sV -p 1-1000 192.168.56.10
```
**Result:** [Add your findings here — e.g. "Detected 23 connection attempts within 4 seconds. Alert fired."]  
**Screenshot:** [`/screenshots/port-scan-detection.png`](screenshots/port-scan-detection.png)

---

### Simulation 3 — LSASS Access (Credential Dumping Indicator)
```powershell
# Trigger Sysmon Event ID 10 by accessing LSASS process
Get-Process lsass
```
**Result:** [Add your findings here — e.g. "Sysmon Event ID 10 captured. SourceImage and GrantedAccess logged."]  
**Screenshot:** [`/screenshots/lsass-detection.png`](screenshots/lsass-detection.png)

---

## Key Findings

> ✏️ *Fill this in as you complete the lab — this section is what impresses hiring managers most*

- **Finding 1:** [e.g. "Windows native event logs missed X but Sysmon captured it via Event ID 10"]
- **Finding 2:** [e.g. "Brute force alerts had 2 false positives — tuned the threshold from 3 to 5 failures"]
- **Finding 3:** [e.g. "Port scan generated 847 events in under 10 seconds — baseline established for alerting"]

---

## Screenshots

| What | File |
|------|------|
| Splunk Dashboard | `screenshots/splunk-dashboard.png` |
| Brute Force Alert Firing | `screenshots/brute-force-alert.png` |
| Sysmon Events in Splunk | `screenshots/sysmon-events.png` |
| Port Scan Detection | `screenshots/port-scan-detection.png` |
| LSASS Access Alert | `screenshots/lsass-detection.png` |
| VM Architecture | `screenshots/vm-setup.png` |

> ✏️ *Replace each entry with an actual image once your lab is running:*
> `![Dashboard](screenshots/splunk-dashboard.png)`

---

## How to Reproduce

1. Clone this repo:
```bash
git clone https://github.com/[your-username]/siem-home-lab.git
cd siem-home-lab
```

2. Follow the full setup guide: [`/docs/setup-guide.md`](docs/setup-guide.md)

3. Use the Sysmon config in `/configs/sysmon-config.xml`

4. Import the Splunk dashboard from `/dashboards/soc-dashboard.xml` via:  
   Splunk UI → Dashboards → Import

5. Run the attack simulations in `/simulations/` and verify detections fire

---

## Lessons Learned

> ✏️ *Fill this in as you go — even short notes show growth to hiring managers*

- [e.g. "Sysmon dramatically improved detection quality over native Windows logs alone"]
- [e.g. "SPL stats vs timechart — learned when to use each for different alert types"]
- [e.g. "Tuning alert thresholds to reduce false positives is harder than writing the initial rule"]

---

## Next Steps

- [ ] Add Elastic SIEM as an alternative setup
- [ ] Integrate Project 2 — Network Traffic Analysis with Suricata
- [ ] Add AWS CloudTrail log ingestion (Project 4)
- [ ] Write automated attack simulation script

---

## Author

**Muhammed Shamil**  
IT Support Analyst → SOC Analyst  
📍 Winnipeg, Manitoba, Canada  
🔗 [LinkedIn](https://linkedin.com/in/your-profile) | 📧 mohdshamil584@gmail.com

---

*Part of my SOC Analyst portfolio — built to demonstrate hands-on security skills beyond certifications.*
