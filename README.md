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
```
## Project Structrue

```bash
SentinelSSH/
├── app.py                 # Application entry point
├── src/
│   ├── attack_events.py   # Attack detection rules
│   ├── get_data.py        # Log parsing logic
│   ├── parse_data.py      # Aggregation and severity scoring
│   ├── generate_report.py # Report generation
│   └── cli.py             # Command-line interface
├── OpenSSH_2k.log         # Sample log file
└── README.md
```
## Usage

### Show report in terminal
```bash
python app.py show --path OpenSSH_2k.log
```

### Show only top 5 attacking IPs
```bash
python app.py show --top 5 --path OpenSSH_2k.log
```

### Output raw JSON instead of formatted text
```bash
python app.py show --json --path OpenSSH_2k.log
```

### Write to a file
```bash
python app.py write --top 10 --out report.json --path OpenSSH_2k.log
```

## Example Output
```bash
=== SSH THREAT REPORT ===
Generated at : 2026-01-30T18:55:21Z\n
Total IPs   : 24
Total Events: 612

1. IP: 187.141.143.180
   Risk Level   : CRITICAL
   Severity     : 412
   Total Events : 184
   Reasons:
     - Privileged account (root) brute-force detected (46 attempts)
     - Automated brute-force detected (80 attempts)
     - SSH brute-force attempts detected (29 attempts)
     - Username enumeration activity (29 attempts)
```

## Severity Scoring
```bash
| Attack Type                   | Weight |
| ----------------------------- | ------ |
| Username Enumeration          | 1      |
| SSH Bruteforce                | 2      |
| Automated Bruteforce          | 3      |
| Privileged Account Bruteforce | 5      |
```


## Install locally as Pip

### First Download the project, go into its root. I.e: SentinelSSH and execute the following command.
```bash
pip install -e .
```
```bash
sentinelssh scan
```
