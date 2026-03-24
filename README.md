# Real-Time Hotspot Monitor 🚀

A highly performant, real-time hotspot monitoring and device detection system built with Python, FastAPI, Scapy, and Chart.js.

## Features
- **Auto Device Detection**: Automatically scans your Wi-Fi/Mobile Hotspot subnet (default `192.168.43.1/24`) to detect connected devices using ARP broadcasting.
- **Hostname Resolution**: Resolves IP addresses into their registered Hostnames using NetBIOS/DNS.
- **Real-Time Bandwidth Tracking**: Utilizes `scapy` packet sniffing to intercept and calculate the cumulative data usage (in bytes) of each IP Address.
- **FastAPI Backend**: A lightweight and exceptionally fast REST API serving the device and usage data asynchronously.
- **Dynamic Dashboard**: A beautiful Dark-Mode HTML/CSS/JS frontend showcasing live devices, highlighting the top data consumer, and tracking live data on an interactive `Chart.js` graph.
- **Smart Alerting**: Logs any connected, disconnected, or newly joined "Unknown" devices to the console in real-time.

## Project Structure
```text
project/
├── main.py              # Orchestrator tying all modules together + Alerts
├── api.py               # FastAPI backend routing and static serving
├── monitor.py           # Scapy packet interception & byte counting
├── scanner.py           # Subnet ARP scanning logic
├── templates/
│   └── index.html       # The Dashboard UI Layout
└── static/
    ├── css/style.css    # Premium dark-mode UI styling
    └── js/dashboard.js  # Frontend fetching logic & Chart.js rendering
```

## Installation
Ensure you have Python 3.8+ installed.

```bash
pip install fastapi uvicorn scapy
```
*Note for Windows users*: Packet sniffing requires an underlying packet capture library. Ensure you have [Npcap](https://npcap.com/) or WinPcap installed.

## Running the Application
The app must be run with **Administrator** or **Root** privileges to successfully monitor packets.

1. Open an elevated terminal (Run as Administrator or use `sudo`).
2. Navigate to the project directory.
3. Start the application:
```bash
python main.py
```
*(On Linux, use `sudo python3 main.py`)*

## Accessing the Dashboard
Once the system reports `Starting backend API on 0.0.0.0:8000`, open your web browser and go to:
**[http://localhost:8000](http://localhost:8000)**

You'll instantly see all devices connected to your network and their real-time data consumption!
