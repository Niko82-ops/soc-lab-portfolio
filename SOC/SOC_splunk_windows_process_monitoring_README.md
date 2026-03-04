# Splunk Windows Process Monitoring (SOC Lab)

## Overview

This project demonstrates how to use **Splunk Enterprise** to monitor Windows systems and detect suspicious process execution events.

The lab simulates a small SOC environment where Windows logs are collected using **Splunk Universal Forwarder** and analyzed through **custom SPL queries, dashboards, and alerts**.

The focus of this project is detecting **Windows process creation events (Event ID 4688)** which are commonly used in threat detection and incident investigations.

---

## Lab Architecture

The lab environment includes:

* **Splunk Enterprise Server**
* **Splunk Universal Forwarder**
* **Windows Event Logs ingestion**
* **Custom SPL detection queries**
* **SOC Monitoring Dashboard**
* **Security Alert for suspicious PowerShell execution**

Data flow:

Windows Host
⬇
Splunk Universal Forwarder
⬇
Splunk Enterprise (Indexing & Analysis)

---

## Data Source

The following Windows logs were collected:

* **Windows Security Event Logs**
* Event ID **4688 – Process Creation**

These logs allow SOC analysts to detect:

* Suspicious PowerShell execution
* Unauthorized process creation
* Potential attacker activity

---

## Detection Queries (SPL)

### Process Creation Detection

```
index=wineventlog EventCode=4688
| rex field=Message "(New Process Name|Nome nuovo processo)\s*:\s+(?<process>[^\r\n]+)"
| stats count as occorrenze by process
| sort - occorrenze
| head 20
```

This query identifies the most frequently executed processes.

---

### PowerShell Execution Detection

```
index=wineventlog EventCode=4688 powershell
| table _time host Message
| head 20
```

This query detects PowerShell executions, which are often used by attackers.

---

## Dashboard

A **SOC Monitoring Dashboard** was created in Splunk containing:

* Top Executed Processes
* Process Creation Timeline
* PowerShell Execution Detection Table

This dashboard provides SOC analysts with a quick overview of process activity on monitored systems.

---

## Alert Detection

A Splunk alert was created to detect suspicious PowerShell execution.

Alert configuration:

* **Search query:** PowerShell detection query
* **Trigger condition:** number of results > 0
* **Schedule:** Daily execution
* **Severity:** Medium

The alert triggers whenever PowerShell activity is detected.

---

## Screenshots

(Add screenshots of the following)

* Splunk search results
* Event ID 4688 logs
* SOC dashboard panels
* Alert configuration
* Splunk forwarder connection

---

## Skills Demonstrated

This project demonstrates:

* SIEM configuration
* Log ingestion
* Security event monitoring
* SPL query development
* Dashboard creation
* SOC alert configuration

Technologies used:

* Splunk Enterprise
* Splunk Universal Forwarder
* Windows Event Logs
* SPL (Search Processing Language)

---
## Full Project Report

The full technical report including configuration steps and screenshots of the lab environment is available in the PDF report.

📄 Monitoraggio_windows_con_Splunk.pdf

This report contains:

- Splunk installation
- Universal Forwarder configuration
- Windows Event Log ingestion
- SPL detection queries
- SOC monitoring dashboard
- Security alert configuration
- Screenshots of the entire lab
## Author

**Domenico Vitale**
SOC / Cybersecurity Lab Portfolio

