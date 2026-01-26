# 🔐 SSH Log Risk Analyzer

A lightweight 🖥️ CLI-based security tool that scans Linux SSH authentication logs and automatically detects 🚨 brute-force attacks, 🕒 unusual login behavior, and 🎯 high-risk IP addresses using rule-based risk scoring.

Built for 🔵 blue-team / SOC-style analysis.

---

## ✨ Features

✅ Parses real OpenSSH / auth.log files  
🚨 Detects SSH brute-force attempts  
🕒 Flags logins during unusual hours (00:00–05:00)  
🎯 Calculates risk score per IP  
📊 Assigns 5 risk levels:
- 🟢 SAFE  
- 🔵 LOW  
- 🟡 MEDIUM  
- 🟠 HIGH  
- 🔴 CRITICAL  

🌍 Classifies IPs as Internal vs External  
🎨 Color-coded terminal output (cross-platform)  
📄 Automatic summary report  
⚙️ Fully configurable via CLI arguments  

---

## 🧠 Risk Scoring Logic

Each IP earns risk points based on behavior:

- ❌ Failed login attempt → +2 points  
- 🌙 Login during unusual hours (00–05) → +2 points  
- 🚨 Detected brute-force activity → +3 points  

Final risk score determines the severity level.

This mimics how basic 🛡️ SIEM / SOC systems prioritize alerts.

---

## 📦 Requirements

- 🐍 Python 3.8+
- 🎨 colorama

Install dependency:
pip install colorama

---

## ▶️ Usage

Basic run:
python analyzer.py --file OpenSSH_2k.log

Custom brute-force threshold:
python analyzer.py --file OpenSSH_2k.log --threshold 5

---

## 🖨️ Example Output

======== Brute-force IPs ========

45.33.32.156    External
192.168.1.10    Internal

======== Risk Scores ========

IP              Risk Score      Level
45.33.32.156    52              🔴 CRITICAL
192.168.1.10    41              🟠 HIGH
10.0.0.8        8               🟢 SAFE

======== SUMMARY REPORT ========

Total unique IPs: 187
Total brute-force IPs: 12
Highest risk IP: 45.33.32.156
Highest risk score: 52

---

## 🎬 Demo Instructions

1️⃣ Open terminal  
2️⃣ Run:
python analyzer.py --file OpenSSH_2k.log  

3️⃣ Scroll through:
- 🚨 Brute-force IPs  
- 🎯 Risk scores  
- 📊 Summary report  

⏱️ Demo takes ~30–45 seconds.

---

## 🏆 Why This Project Matters

Most beginner security tools:
❌ Use fake data  
❌ Hide logic behind graphs  
❌ Overuse unnecessary ML  

This project focuses on:
✅ Real-world logs  
✅ Transparent, explainable logic  
✅ Defender-first thinking  

---

## 🚀 Future Improvements

- 📤 JSON export
- 🌍 Geo-IP enrichment
- ⚡ Burst attack detection
- 🌐 Web UI wrapper

---

## 👤 Author

Built by Nonsense0909688  
(Global Hack Week submission)

## Demo
<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/d75ca324-6926-4e15-bb05-514869ad8736" />
<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/0765f06b-72b5-4011-9328-6ccf8c65a880" />
<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/7527dede-f502-445b-b320-c1ec56dcce73" />


