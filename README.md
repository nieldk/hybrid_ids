# Hybrid Intrusion Detection System (IDS) in Python

A real-time Intrusion Detection System built in Python using both **signature-based detection** and **machine learning-based anomaly detection**.

## Features

- Real-time packet sniffing using Scapy
- Signature-based alerts for suspicious IPs and ports
- Anomaly detection with Isolation Forest (Scikit-learn)
- Terminal alerts with timestamps and colorized output
- Easily extendable and modular Python code

## Demo

```bash
sudo python3 hybrid_ids.py
```
```
[*] Starting hybrid IDS on eth0...
[+] Anomaly model trained on 200 samples
[!] ALERT (2025-05-13 21:48:30): Anomalous packet detected: 192.168.1.15 -> 10.0.0.5
[!] ALERT (2025-05-13 21:48:31): Suspicious IP address detected: 192.168.1.100 -> 192.168.1.10
[!] ALERT (2025-05-13 21:48:35): Suspicious port activity: 192.168.1.5:4444 -> 10.0.0.2:80
```

## Installation

Install Python dependencies:

```bash
pip install -r requirements.txt
