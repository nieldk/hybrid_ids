# Hybrid Intrusion Detection System (IDS) in Python

A real-time Intrusion Detection System built in Python using both **signature-based detection** and **machine learning-based anomaly detection**.

## Features

- Real-time packet sniffing using Scapy
- Signature-based alerts for suspicious IPs and ports
- Anomaly detection with Isolation Forest (Scikit-learn)
- Terminal alerts with timestamps and colorized output
- Blocking detected source IPs with iptables (IPS functionality)
- Easily extendable and modular Python code

## Demo

```bash
sudo python3 hybrid_ids.py
```
![screenshot](demo_IPS.PNG)

# Installation Guide: Hybrid IDS/IPS with Systemd Integration

This guide walks you through installing and running the Python-based Hybrid Intrusion Detection & Prevention System (IDS/IPS) as a Linux systemd service.

---

## Requirements

- Python 3
- `pip` with required packages (`scapy`, `pandas`, `sklearn`, `colorama`)
- Root privileges (required for packet sniffing and `iptables`)
- Linux system with `systemd` (Ubuntu, Debian, CentOS, etc.)

---

## Install Dependencies

```bash
sudo apt update
sudo apt install python3-pip iptables -y
pip3 install scapy pandas scikit-learn colorama
```

---

## Copy the Script

Assuming you have the file `hybrid_ids.py`:

```bash
sudo cp hybrid_ids.py /opt/
sudo chmod +x /opt/hybrid_ids.py
```

---

## Create systemd Service File

```bash
sudo nano /etc/systemd/system/ids-ips.service
```

Paste the following content:

```ini
[Unit]
Description=Hybrid IDS/IPS Python Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/hybrid_ids.py
WorkingDirectory=/opt
Restart=on-failure
StandardOutput=journal
StandardError=journal
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

Save and exit.

---

## Enable and Start the Service

```bash
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable ids-ips.service
sudo systemctl start ids-ips.service
```

---

## View Logs and Status

```bash
sudo systemctl status ids-ips.service
sudo journalctl -u ids-ips.service -f
```

---

## Stop and Disable

```bash
sudo systemctl stop ids-ips.service
sudo systemctl disable ids-ips.service
```

---

## Important Notes

- This service runs as `root` because raw socket access and firewall management (`iptables`) require elevated privileges.
- Customize the script or service file paths if needed.

## Happy hunting! 

