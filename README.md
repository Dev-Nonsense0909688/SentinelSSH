# SentinelSSH  
Smart SSH Log Threat Analyzer

SentinelSSH is a command-line tool that analyzes SSH authentication logs and turns them into structured security insights.  
It detects common SSH attack patterns, ranks attacking IPs by severity, and generates readable security reports.

The goal of SentinelSSH is to convert noisy, unstructured log data into clear and actionable threat information.

---

## Features

- Parses raw SSH authentication logs
- Detects common SSH attacks:
  - Privileged (root) brute-force
  - SSH brute-force attempts
  - Username enumeration
  - Automated or botnet-based attacks
- Aggregates attacks per IP address
- Calculates a weighted severity score
- Assigns risk levels (LOW, MEDIUM, HIGH, CRITICAL)
- Ranks the most dangerous attacking IPs
- Outputs results in terminal or JSON
- Simple, dependency-free Python code

---

## Requirements

- Python 3.10 or newer
- No external libraries required

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/SentinelSSH.git
cd SentinelSSH
