import os
import platform

# Network Configuration
NETWORK_INTERFACE = "enp0s3"
SCAN_SUBNET = "192.168.1.0/24"

# System Settings
SYSTEM_MODE = "MANUAL" # Default mode: MANUAL or AUTO
LOG_FILE = "logs/bandwidth.log"
DEVICES_FILE = "devices.json"

# Auth Settings
ADMIN_USER = "admin"
ADMIN_PASS = "admin123" # In production, use environment variables
SECRET_KEY = "super-secret-key-for-auth"

# Monitoring
REFRESH_INTERVAL = 1 # Seconds
HISTORY_LIMIT = 50

# Smart Scanning
SMART_SCAN_TIMEOUT = 40
SMART_SCAN_MAX_HOSTS = 254
SMART_SCAN_PING_SWEEP = True
SMART_SCAN_INCLUDE_HOSTNAME_RESOLVE = True

# AI Prediction
AI_WINDOW_SIZE = 10

# OS Detection
IS_LINUX = platform.system() == "Linux"

# Dependencies
REQUIRED_TOOLS = ["nmap", "tc", "iptables"] if IS_LINUX else []
