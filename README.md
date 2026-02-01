# AI Network Packet Sniffer

## Description
This project implements a network packet analyser with AI-based anomaly detection using Python and Tkinter. It captures network traffic via raw sockets, parses multiple protocols (TCP, UDP, and ICMP) and applies a machine learning model (Isolation Forest) to identify suspicious activities such as simulated port scans and DDoS attacks.

## Features

- **Real-time Packet Capture**: Live network traffic monitoring with detailed packet viewing
- **AI Anomaly Detection**: Machine learning-based detection of network anomalies
- **Attack Simulation**: Built-in GUI controls to simulate port scans and DDoS traffic for testing the anomaly detection system

## Project Structure

```
PacketSniffer/
├── packet_gui.py          # Main GUI application
├── packetsniffer.py       # Core packet sniffer logic
├── anomaly_detector.py    # AI anomaly detection
├── packet_details.py      # Detailed packet inspection window
├── run_sniffer.bat        # Windows launcher script
├── requirements.txt       # Python dependencies
└── README.md
```

## Installation & Setup

1. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run as Administrator** (Required for raw socket access on Windows):
   - Right-click `run_sniffer.bat` → "Run as administrator"
   - Or Right-click VS Code → "Run as administrator" and `run_sniffer.bat` normally

## Usage Guide

### 1. Start Packet Capture
- Click "Start Capture" to begin monitoring network traffic
- Packets appear in the main table and double-click any packet to view detailed information

### 2. Set Up Anomaly Detection  
- Click "Collect Baseline" to start learning normal traffic patterns
- Let normal traffic flow for 30+ windows (more is better)
- Click "Train AI Model" to train the anomaly detection system

### 3. Monitor for Anomalies
- Once trained, the AI continuously monitors for unusual patterns
- Anomalies appear in the right panel with detailed analysis

### 4. Test with Simulations
- Use "Simulate Port Scan" to test rapid port scanning detection
- Use "Simulate DDoS" to test high-volume attack detection
