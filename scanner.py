import subprocess
import re
import json
import os
from logger import logger
from config import DEVICES_FILE, SCAN_SUBNET, IS_LINUX

class NetworkScanner:
    def __init__(self):
        self.devices = []
        self.load_devices()

    def load_devices(self):
        if os.path.exists(DEVICES_FILE):
            try:
                with open(DEVICES_FILE, 'r') as f:
                    self.devices = json.load(f)
            except Exception:
                self.devices = []

    def _infer_device_type(self, name):
        name_lower = (name or "").lower()
        if any(token in name_lower for token in ["iphone", "android", "mobile", "phone", "pixel", "redmi", "samsung"]):
            return "Mobile"
        if any(token in name_lower for token in ["laptop", "notebook", "macbook", "thinkpad"]):
            return "Laptop"
        if any(token in name_lower for token in ["pc", "desktop", "workstation"]):
            return "PC"
        return "Unknown"

    def _normalize_device(self, device):
        normalized = {
            "ip": device.get("ip", ""),
            "mac": device.get("mac", "00:00:00:00:00:00"),
            "name": device.get("name", "Unknown Device"),
            "role": device.get("role", "Guest"),
            "bandwidth_limit": device.get("bandwidth_limit", 5),
            "status": device.get("status", "ACTIVE")
        }
        normalized["device_type"] = device.get("device_type") or self._infer_device_type(normalized["name"])
        return normalized

    def _merge_discovered(self, discovered):
        existing_by_ip = {device.get('ip'): device for device in self.devices if device.get('ip')}
        for discovered_device in discovered:
            normalized = self._normalize_device(discovered_device)
            ip = normalized['ip']
            if not ip:
                continue

            if ip in existing_by_ip:
                existing = existing_by_ip[ip]
                for key in ["mac", "name", "device_type"]:
                    value = normalized.get(key)
                    if value and value not in ["Unknown Device", "00:00:00:00:00:00", "Unknown"]:
                        existing[key] = value
                existing.setdefault("role", "Guest")
                existing.setdefault("bandwidth_limit", 5)
                existing.setdefault("status", "ACTIVE")
            else:
                self.devices.append(normalized)
                existing_by_ip[ip] = normalized
                logger.info(f"New device discovered: {ip} ({normalized.get('mac', 'N/A')})")

    def scan_network_nmap(self):
        """
        Scans the network using nmap for detailed info.
        """
        logger.info("Scanning network using nmap...")
        try:
            cmd = ["nmap", "-sn", SCAN_SUBNET]
            output = subprocess.check_output(cmd, timeout=30).decode('utf-8', errors='ignore')
            return self.parse_nmap_output(output)
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return self.scan_network_arp()

    def scan_network_arp(self):
        """
        Scans the network using 'arp -a'.
        This is a basic method that works on both Windows and Linux.
        """
        logger.info("Scanning network using ARP...")
        try:
            output = subprocess.check_output(['arp', '-a']).decode('utf-8', errors='ignore')
            return self.parse_arp_output(output)
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
            return []

    def parse_nmap_output(self, output):
        devices = []
        lines = output.split('\n')
        current_device = {}
        for line in lines:
            if 'Nmap scan report for' in line:
                if current_device:
                    devices.append(current_device)
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                hostname_match = re.search(r'(\w+)\s*\(', line)
                current_device = {
                    "ip": ip_match.group(1) if ip_match else "Unknown",
                    "name": hostname_match.group(1) if hostname_match else "Unknown Device",
                    "role": "Guest",
                    "bandwidth_limit": 5,
                    "status": "ACTIVE"
                }
            elif 'MAC Address:' in line:
                mac_match = re.search(r'([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', line)
                if mac_match:
                    current_device["mac"] = mac_match.group(1).replace('-', ':').upper()
        if current_device:
            devices.append(current_device)
        return devices

    def parse_arp_output(self, output):
        devices = []
        # Regex for IP and MAC (generic enough for both OS)
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        mac_pattern = r'([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})'
        
        lines = output.split('\n')
        for line in lines:
            ips = re.findall(ip_pattern, line)
            macs = re.findall(mac_pattern, line)
            if ips and macs:
                devices.append({
                    "ip": ips[0],
                    "mac": macs[0].replace('-', ':').upper(),
                    "name": "Unknown Device",
                    "role": "Guest",
                    "bandwidth_limit": 5,
                    "status": "ACTIVE"
                })
        return devices

    def _ping_ip(self, ip):
        try:
            if IS_LINUX:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            else:
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            return result.returncode == 0
        except Exception:
            return False

    def add_or_update_manual_ip(self, ip):
        if not ip:
            return {"status": "error", "message": "IP is required"}

        try:
            import ipaddress
            ipaddress.ip_address(ip)
        except ValueError:
            return {"status": "error", "message": "Invalid IP format"}

        is_reachable = self._ping_ip(ip)
        existing = next((device for device in self.devices if device.get("ip") == ip), None)

        if existing:
            existing["status"] = "ACTIVE" if is_reachable else existing.get("status", "INACTIVE")
            existing.setdefault("device_type", self._infer_device_type(existing.get("name", "Unknown Device")))
            self.save_devices()
            return {
                "status": "success",
                "reachable": is_reachable,
                "device": existing,
                "message": "Device already exists and was refreshed"
            }

        device = self._normalize_device({
            "ip": ip,
            "name": f"Manual-{ip}",
            "role": "Guest",
            "bandwidth_limit": 5,
            "status": "ACTIVE" if is_reachable else "INACTIVE"
        })
        self.devices.append(device)
        self.save_devices()
        return {
            "status": "success",
            "reachable": is_reachable,
            "device": device,
            "message": "Device added by manual IP"
        }

    def update_device_list(self):
        """
        Discovers new devices and updates the device database.
        """
        discovered = self.scan_network_nmap() if IS_LINUX else self.scan_network_arp()
        
        # Simulation for Demo (if no devices found)
        if not discovered and not IS_LINUX:
            discovered = [
                {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:01", "name": "Admin-PC", "role": "Admin", "bandwidth_limit": 100, "device_type": "PC", "status": "ACTIVE"},
                {"ip": "192.168.1.15", "mac": "AA:BB:CC:DD:EE:02", "name": "Teacher-Laptop", "role": "Teacher", "bandwidth_limit": 50, "device_type": "Laptop", "status": "ACTIVE"},
                {"ip": "192.168.1.22", "mac": "AA:BB:CC:DD:EE:03", "name": "Student-Phone", "role": "Student", "bandwidth_limit": 10, "device_type": "Mobile", "status": "ACTIVE"},
                {"ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:04", "name": "Guest-Device", "role": "Guest", "bandwidth_limit": 5, "device_type": "Unknown", "status": "ACTIVE"},
            ]

        self._merge_discovered(discovered)
        
        self.save_devices()
        return self.devices

    def save_devices(self):
        try:
            with open(DEVICES_FILE, 'w') as f:
                json.dump(self.devices, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save devices: {e}")

scanner = NetworkScanner()
