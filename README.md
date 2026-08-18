# Log-Based Threat Detection Tool

A Python-based security log analysis tool that identifies suspicious authentication activity and converts raw log events into structured security alerts.

> **Project Type:** Cybersecurity / SOC / Blue Team  
> **Status:** Academic & Portfolio Project

---

## Project Objective

SOC analysts frequently investigate authentication logs to identify suspicious activity such as repeated login failures, credential attacks, and possible account compromise.

This project demonstrates a simple rule-based detection workflow:

**Authentication Logs → Log Parsing → Detection Rules → Alert Generation → Incident Report**

---

## Detection Capabilities

The tool currently detects:

### 1. Brute-Force Attacks
Identifies repeated failed authentication attempts occurring within a defined time window.

### 2. Credential Stuffing
Detects repeated authentication attempts associated with the same source IP and multiple targeted accounts.

### 3. Possible Account Compromise
Correlates failed authentication attempts with a subsequent successful login to identify potentially compromised accounts.

---

## Features

- Authentication log parsing
- Time-based brute-force detection
- Source-IP based credential-stuffing detection
- Failed-login and successful-login correlation
- Severity-based alert generation
- Structured security reports
- Sample authentication logs for testing
- Modular Python implementation

---

## Detection Workflow

```text
Authentication Logs
        │
        ▼
     Log Parser
        │
        ▼
 Detection Engine
        │
   ┌────┼───────────────┐
   ▼    ▼               ▼
Brute  Credential     Account
Force  Stuffing       Compromise
   │    │               │
   └────┴───────┬───────┘
                ▼
          Security Alerts
                │
                ▼
          Alert Reporter
                │
                ▼
          Incident Report
