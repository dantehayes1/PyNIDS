# PyNIDS

PyNIDS (Python Network Intrusion Detection System) is a lightweight network monitoring tool built with Python. It captures and analyzes network packets to detect suspicious or potentially malicious activity in real time.

## 🚀 Project Goals

- ✅ Learn real-world cybersecurity practices
- ✅ Build a portfolio-ready Python tool
- ✅ Gain hands-on experience with packet sniffing
- ✅ Practice using libraries like `scapy` and `argparse`

## 🧠 What It Does

- Captures live network traffic
- Analyzes packet headers for potential threats
- Logs alerts to a local file (`logs/alerts.log`)
- Uses customizable filters (IP, port, protocol)

## 🛠️ Technologies Used

- Python 3
- Scapy
- Argparse
- Logging

## 📁 Project Structure

PyNIDS/
├── logs/
│ └── alerts.log
├── src/
│ ├── core/
│ │ ├── sniffer.py
│ │ ├── parser.py
│ │ └── logger.py
│ └── main.py
├── README.md
└── requirements.txt

## 🧪 How to Run

1. Install dependencies:

```bash

pip install -r requirements.txt

2. python src/main.py --interface eth0

3. logs/alerts.log


