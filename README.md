# azure-honeypot-siem
A cybersecurity honeypot project using Azure VM, Microsoft Sentinel, and KQL to monitor and visualize brute-force RDP attacks.

# Azure Honeypot SIEM Project

This project simulates real-world brute-force attacks using a Windows 10 virtual machine on Microsoft Azure, integrated with Microsoft Sentinel. It demonstrates core skills in security event logging, log analysis, KQL, and SIEM dashboards.

## 🛠️ Tools & Technologies
- **Azure Virtual Machine** (Windows 10)
- **Microsoft Sentinel** (SIEM)
- **Log Analytics Workspace**
- **Kusto Query Language (KQL)**
- **Event Viewer**
- **Sentinel Workbooks**
- **Watchlists (IP Geolocation)**

---

## 📌 Project Architecture

![Azure Honeypot Architecture](path-to-diagram.png)  
*Ask me to help generate one if you need it!*

---

## 📖 Project Overview

### 1. 🧱 VM Setup & Exposure
- Deployed a Windows 10 VM in Azure
- Opened inbound RDP (port 3389) in NSG to attract attackers
- Disabled Windows Firewall to simulate poor security

### 2. 📊 Logging Attacks
- Logged failed login attempts (Event ID 4625) in Event Viewer
- Forwarded logs to Log Analytics via Microsoft Sentinel

### 3. 🔍 KQL Analysis
```kql
SecurityEvent
| where EventID == 4625
| summarize count() by IpAddress, Account, TimeGenerated
| sort by count_ desc
```
### 4. 🌍 Geo-IP Enrichment
Imported geoip-summarized.csv as a Sentinel Watchlist

Used ipv4_lookup() to map IP addresses to geolocations

### 5. 🗺️ Attack Map Visualization
Created a Sentinel Workbook with a world map showing attack origins

JSON-based query to visualize data by IP country

## 🎯 Learning Outcomes
Configured a working honeypot in Azure

Used KQL to query and analyze real-world attack logs

Built a geolocation-enhanced attack visualization

Practiced SIEM log ingestion, watchlists, and workbook creation



