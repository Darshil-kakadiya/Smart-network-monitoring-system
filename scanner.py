import subprocess
import re
import json
import os
import socket
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from logger import logger
from config import (
    DEVICES_FILE,
    SCAN_SUBNET,
    IS_LINUX,
    SMART_SCAN_TIMEOUT,
    SMART_SCAN_MAX_HOSTS,
    SMART_SCAN_MAX_SUBNETS,
    SMART_SCAN_PING_SWEEP,
    SMART_SCAN_INCLUDE_HOSTNAME_RESOLVE,
    HOTSPOT_ONLY_MODE,
    HOTSPOT_INTERFACE_KEYWORDS,
    HOTSPOT_SUBNET_HINTS,
)

class NetworkScanner:
    def __init__(self):
        self.devices = []
        self.local_hostname = socket.gethostname()
        self.local_ips = self._get_local_ips()
        self.local_ipv4_networks = self._get_local_ipv4_networks()
        self.hotspot_ipv4_networks = self._get_hotspot_ipv4_networks()
        self.last_scan_details = {
            "mode": "startup",
            "scanned_subnets": [],
            "source_breakdown": {},
            "discovered_count": 0,
            "duration_ms": 0,
            "timestamp": int(time.time())
        }
        self.load_devices()

    def _record_scan_details(self, mode, subnets, discovered):
        source_breakdown = {}
        for item in discovered or []:
            for source in item.get("scan_sources", []):
                source_breakdown[source] = source_breakdown.get(source, 0) + 1

        self.last_scan_details = {
            "mode": mode,
            "scanned_subnets": list(subnets or []),
            "source_breakdown": source_breakdown,
            "discovered_count": len(discovered or []),
            "known_devices": len(self.devices),
            "duration_ms": 0,
            "timestamp": int(time.time())
        }

    def _set_scan_duration(self, started_at):
        try:
            self.last_scan_details["duration_ms"] = int((time.time() - started_at) * 1000)
        except Exception:
            self.last_scan_details["duration_ms"] = 0

    def _get_local_ips(self):
        ips = set()
        try:
            for item in socket.getaddrinfo(socket.gethostname(), None):
                candidate = item[4][0]
                try:
                    ip_obj = ipaddress.ip_address(candidate)
                    if not ip_obj.is_loopback:
                        ips.add(candidate)
                except ValueError:
                    continue
        except Exception:
            pass
        return ips

    def _get_local_ipv4_networks(self):
        networks = []

        if IS_LINUX:
            try:
                output = subprocess.check_output(["ip", "-o", "-f", "inet", "addr", "show"], timeout=6).decode("utf-8", errors="ignore")
                for line in output.splitlines():
                    match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
                    if not match:
                        continue
                    cidr = match.group(1)
                    iface_network = ipaddress.ip_interface(cidr).network
                    if iface_network.is_loopback:
                        continue
                    networks.append(iface_network)
            except Exception as exc:
                logger.warning(f"Dynamic subnet detection (linux) failed: {exc}")
        else:
            try:
                output = subprocess.check_output(["ipconfig"], timeout=8).decode("utf-8", errors="ignore")
                ipv4 = None
                mask = None
                for raw_line in output.splitlines():
                    line = raw_line.strip()
                    ipv4_match = re.search(r"IPv4 Address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
                    if ipv4_match:
                        ipv4 = ipv4_match.group(1)
                        continue

                    mask_match = re.search(r"Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
                    if mask_match:
                        mask = mask_match.group(1)

                    if ipv4 and mask:
                        try:
                            iface = ipaddress.IPv4Interface(f"{ipv4}/{mask}")
                            if not iface.ip.is_loopback:
                                networks.append(iface.network)
                        except Exception:
                            pass
                        ipv4 = None
                        mask = None
            except Exception as exc:
                logger.warning(f"Dynamic subnet detection (windows) failed: {exc}")

        unique_networks = []
        seen = set()
        for network in networks:
            value = str(network)
            if value in seen:
                continue
            seen.add(value)
            unique_networks.append(network)

        return unique_networks

    def _get_hotspot_ipv4_networks(self):
        selected = []

        if IS_LINUX:
            selected.extend(self.local_ipv4_networks)
        else:
            try:
                output = subprocess.check_output(["ipconfig"], timeout=8).decode("utf-8", errors="ignore")
                current_adapter = ""
                current_ipv4 = None
                current_mask = None
                for raw_line in output.splitlines():
                    adapter_match = re.match(r"^([^\r\n]+adapter\s+[^:]+):\s*$", raw_line, re.IGNORECASE)
                    if adapter_match:
                        current_adapter = adapter_match.group(1).strip().lower()
                        current_ipv4 = None
                        current_mask = None
                        continue

                    line = raw_line.strip()
                    ipv4_match = re.search(r"IPv4 Address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
                    if ipv4_match:
                        current_ipv4 = ipv4_match.group(1)
                        continue

                    mask_match = re.search(r"Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
                    if mask_match:
                        current_mask = mask_match.group(1)

                    if current_ipv4 and current_mask:
                        try:
                            iface = ipaddress.IPv4Interface(f"{current_ipv4}/{current_mask}")
                            is_hotspot_like = any(token in current_adapter for token in HOTSPOT_INTERFACE_KEYWORDS)
                            if not iface.ip.is_loopback and is_hotspot_like:
                                selected.append(iface.network)
                        except Exception:
                            pass
                        current_ipv4 = None
                        current_mask = None
            except Exception as exc:
                logger.warning(f"Hotspot subnet detection failed: {exc}")

        if not selected:
            selected.extend(self.local_ipv4_networks)

        if not selected and HOTSPOT_SUBNET_HINTS:
            for hint in HOTSPOT_SUBNET_HINTS:
                try:
                    selected.append(ipaddress.ip_network(hint, strict=False))
                except Exception:
                    continue

        unique_networks = []
        seen = set()
        for network in selected:
            value = str(network)
            if value in seen:
                continue
            seen.add(value)
            unique_networks.append(network)
        return unique_networks

    def _is_in_hotspot_network(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
        except Exception:
            return False

        if not HOTSPOT_ONLY_MODE:
            return True

        candidate_networks = self.hotspot_ipv4_networks or self.local_ipv4_networks
        if not candidate_networks:
            try:
                candidate_networks = [ipaddress.ip_network(SCAN_SUBNET, strict=False)]
            except Exception:
                candidate_networks = []

        if not candidate_networks:
            return True

        return any(ip_obj in network for network in candidate_networks)

    def _friendly_name_for_ip(self, ip):
        if not ip:
            return "Unknown Device"
        suffix = ip.split('.')[-1] if '.' in ip else ip
        return f"Device-{suffix}"

    def _is_usable_host_ip(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_multicast or ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_reserved:
                return False
            if isinstance(ip_obj, ipaddress.IPv4Address) and ip.endswith('.255'):
                return False
            return True
        except ValueError:
            return False

    def _is_usable_host_mac(self, mac):
        if not mac:
            return False
        mac_upper = mac.upper()
        if mac_upper == "FF:FF:FF:FF:FF:FF":
            return False
        if mac_upper.startswith("01:00:5E"):
            return False
        return True

    def _normalize_mac(self, mac):
        if not mac:
            return "00:00:00:00:00:00"
        return mac.replace('-', ':').upper()

    def _resolve_hostname(self, ip):
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            if name:
                return name
        except Exception:
            pass

        if not IS_LINUX:
            try:
                result = subprocess.run(["ping", "-a", "-n", "1", ip], capture_output=True, text=True, timeout=3)
                first_line = (result.stdout or "").splitlines()[0] if result.stdout else ""
                match = re.search(r'Pinging\s+(.+?)\s+\[', first_line)
                if match:
                    name = match.group(1).strip()
                    if name and name != ip:
                        return name
            except Exception:
                pass

        return "Unknown Device"

    def _sanitize_devices(self, devices):
        sanitized = []
        seen_ips = set()
        for device in devices:
            normalized = self._normalize_device(device)
            ip = normalized.get("ip")
            mac = normalized.get("mac", "")

            if not ip or not self._is_usable_host_ip(ip):
                continue
            if not self._is_in_hotspot_network(ip):
                continue
            if not self._is_usable_host_mac(mac):
                normalized["mac"] = "00:00:00:00:00:00"

            if not normalized.get("name") or normalized.get("name") == "Unknown Device":
                normalized["name"] = self._friendly_name_for_ip(ip)

            if normalized.get("detection_confidence") is None:
                normalized["detection_confidence"] = self._calculate_confidence(normalized)
            if not normalized.get("connection_type"):
                normalized["connection_type"] = self._infer_connection_type(
                    normalized.get("name"),
                    normalized.get("mac"),
                    normalized.get("scan_sources", ["legacy"])
                )

            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            sanitized.append(normalized)

        return sanitized

    def cleanup_unnecessary_devices(self):
        before = len(self.devices)
        self.devices = self._sanitize_devices(self.devices)
        after = len(self.devices)
        removed = max(0, before - after)
        self.save_devices()
        return {"removed": removed, "remaining": after}

    def load_devices(self):
        if os.path.exists(DEVICES_FILE):
            try:
                with open(DEVICES_FILE, 'r') as f:
                    loaded = json.load(f)
                    self.devices = self._sanitize_devices(loaded)
                    self.save_devices()
            except Exception:
                self.devices = []

    def _infer_device_type(self, name, ip=None):
        if ip and ip in self.local_ips:
            return "This PC"

        name_lower = (name or "").lower()
        if any(token in name_lower for token in ["iphone", "android", "mobile", "phone", "pixel", "redmi", "samsung", "oneplus", "xiaomi"]):
            return "Mobile"
        if any(token in name_lower for token in ["laptop", "notebook", "macbook", "thinkpad", "book"]):
            return "Laptop"
        if any(token in name_lower for token in ["pc", "desktop", "workstation", "windows", "imac"]):
            return "PC"
        return "Unknown"

    def _infer_connection_type(self, name, mac, scan_sources=None):
        name_lower = (name or "").lower()
        source_text = ' '.join(scan_sources or []).lower()
        mac_prefix = (mac or "")[:8].upper()

        wireless_name_tokens = [
            "iphone", "android", "mobile", "phone", "pixel", "redmi", "samsung", "oneplus", "xiaomi",
            "wifi", "wlan", "tablet", "ipad", "watch"
        ]
        wired_name_tokens = ["desktop", "pc", "workstation", "server", "lan", "ethernet", "printer", "nas"]

        known_wireless_ouis = {
            "D8:96:95", "F4:F5:D8", "FC:FB:FB", "A4:C3:F0", "C8:FF:77", "60:AB:67"
        }

        if any(token in name_lower for token in wireless_name_tokens):
            return "Wireless"
        if any(token in name_lower for token in wired_name_tokens):
            return "Wired"
        if mac_prefix in known_wireless_ouis:
            return "Wireless"
        if "nmap" in source_text and "arp" in source_text:
            return "Wired/Wireless"
        return "Unknown"

    def _calculate_confidence(self, device):
        score = 0
        if device.get("ip") and self._is_usable_host_ip(device.get("ip")):
            score += 35
        if device.get("mac") and device.get("mac") != "00:00:00:00:00:00":
            score += 25
        if device.get("name") and device.get("name") != "Unknown Device":
            score += 15
        if device.get("status") == "ACTIVE":
            score += 10

        source_count = len(set(device.get("scan_sources", [])))
        if source_count >= 2:
            score += 15

        return min(100, score)

    def _hosts_from_subnet(self, subnet=None, max_hosts=None):
        try:
            target_subnet = subnet or self._get_effective_scan_subnet()
            network = ipaddress.ip_network(target_subnet, strict=False)
            hosts = [str(host) for host in network.hosts()]
            host_limit = max_hosts if max_hosts is not None else SMART_SCAN_MAX_HOSTS
            return hosts[:max(1, host_limit)]
        except Exception as exc:
            logger.error(f"Subnet parse failed for {SCAN_SUBNET}: {exc}")
            return []

    def _get_effective_scan_subnets(self):
        try:
            configured = ipaddress.ip_network(SCAN_SUBNET, strict=False)
        except Exception:
            configured = None

        if HOTSPOT_ONLY_MODE:
            hotspot_subnets = [str(network) for network in (self.hotspot_ipv4_networks or [])]
            if hotspot_subnets:
                return hotspot_subnets[:max(1, SMART_SCAN_MAX_SUBNETS)]
            if configured:
                return [str(configured)]

        selected = []
        if configured and self.local_ipv4_networks and any(network.overlaps(configured) for network in self.local_ipv4_networks):
            selected.append(str(configured))
            selected.extend(str(network) for network in self.local_ipv4_networks)
        elif self.local_ipv4_networks:
            selected.extend(str(network) for network in self.local_ipv4_networks)
            logger.warning(
                f"Configured SCAN_SUBNET={SCAN_SUBNET} not aligned with active interfaces. Using dynamic subnets {selected}"
            )
        else:
            selected.append(SCAN_SUBNET)

        deduped = []
        seen = set()
        for subnet in selected:
            if subnet in seen:
                continue
            seen.add(subnet)
            deduped.append(subnet)

        return deduped[:max(1, SMART_SCAN_MAX_SUBNETS)]

    def _get_effective_scan_subnet(self):
        return self._get_effective_scan_subnets()[0]

    def _ping_sweep(self):
        if not SMART_SCAN_PING_SWEEP:
            return []

        subnets = self._get_effective_scan_subnets()
        if not subnets:
            return []

        remaining_budget = max(1, SMART_SCAN_MAX_HOSTS)
        hosts = []
        for index, subnet in enumerate(subnets):
            remaining_subnets = max(1, len(subnets) - index)
            per_subnet_budget = max(1, remaining_budget // remaining_subnets)
            subnet_hosts = self._hosts_from_subnet(subnet=subnet, max_hosts=per_subnet_budget)
            hosts.extend(subnet_hosts)
            remaining_budget -= len(subnet_hosts)
            if remaining_budget <= 0:
                break

        if not hosts:
            return []

        discovered = []
        with ThreadPoolExecutor(max_workers=64) as executor:
            future_map = {executor.submit(self._ping_ip, host): host for host in hosts}
            for future in as_completed(future_map):
                ip = future_map[future]
                try:
                    if future.result():
                        discovered.append({
                            "ip": ip,
                            "name": self._resolve_hostname(ip) if SMART_SCAN_INCLUDE_HOSTNAME_RESOLVE else "Unknown Device",
                            "role": "Guest",
                            "bandwidth_limit": 5,
                            "status": "ACTIVE",
                            "scan_sources": ["ping-sweep"]
                        })
                except Exception:
                    continue
        return discovered

    def _scan_network_neighbors(self):
        if IS_LINUX:
            try:
                output = subprocess.check_output(["ip", "neigh", "show"], timeout=8).decode('utf-8', errors='ignore')
                return self.parse_ip_neigh_output(output)
            except Exception as exc:
                logger.warning(f"ip neigh scan failed: {exc}")
                return []

        try:
            output = subprocess.check_output(['arp', '-a']).decode('utf-8', errors='ignore')
            return self.parse_arp_output(output, source="arp")
        except Exception as exc:
            logger.warning(f"ARP neighbor scan failed: {exc}")
            return []

    def parse_ip_neigh_output(self, output):
        devices = []
        lines = output.split('\n')
        for line in lines:
            ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
            mac_match = re.search(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', line)
            if not ip_match:
                continue

            ip = ip_match.group(1)
            if not self._is_usable_host_ip(ip):
                continue
            if not self._is_in_hotspot_network(ip):
                continue

            mac = self._normalize_mac(mac_match.group(1)) if mac_match else "00:00:00:00:00:00"
            if mac != "00:00:00:00:00:00" and not self._is_usable_host_mac(mac):
                continue

            devices.append({
                "ip": ip,
                "mac": mac,
                "name": self._resolve_hostname(ip),
                "role": "Guest",
                "bandwidth_limit": 5,
                "status": "ACTIVE",
                "scan_sources": ["ip-neigh"]
            })

        return devices

    def _normalize_device(self, device):
        normalized = {
            "ip": device.get("ip", ""),
            "mac": device.get("mac", "00:00:00:00:00:00"),
            "name": device.get("name", "Unknown Device"),
            "role": device.get("role", "Guest"),
            "bandwidth_limit": device.get("bandwidth_limit", 5),
            "status": device.get("status", "ACTIVE"),
            "scan_sources": device.get("scan_sources", ["legacy"])
        }
        if normalized["name"] in ["Unknown Device", ""] and normalized["ip"]:
            resolved = self._resolve_hostname(normalized["ip"])
            if resolved:
                normalized["name"] = resolved

        if normalized["ip"] in self.local_ips:
            normalized["name"] = f"{self.local_hostname} (This PC)"

        normalized["device_type"] = device.get("device_type") or self._infer_device_type(normalized["name"], normalized["ip"])
        normalized["mac"] = self._normalize_mac(normalized["mac"])
        normalized["connection_type"] = device.get("connection_type") or self._infer_connection_type(
            normalized["name"], normalized["mac"], normalized.get("scan_sources", [])
        )
        normalized["detection_confidence"] = device.get("detection_confidence")
        if normalized["detection_confidence"] is None:
            normalized["detection_confidence"] = self._calculate_confidence(normalized)
        return normalized

    def _merge_discovered(self, discovered):
        existing_by_ip = {device.get('ip'): device for device in self.devices if device.get('ip')}
        for discovered_device in discovered:
            normalized = self._normalize_device(discovered_device)
            ip = normalized['ip']
            if not ip:
                continue
            if not self._is_in_hotspot_network(ip):
                continue

            if ip in existing_by_ip:
                existing = existing_by_ip[ip]
                for key in ["mac", "name", "device_type"]:
                    value = normalized.get(key)
                    if value and value not in ["Unknown Device", "00:00:00:00:00:00", "Unknown"]:
                        existing[key] = value
                existing_sources = set(existing.get("scan_sources", []))
                discovered_sources = set(normalized.get("scan_sources", []))
                existing["scan_sources"] = sorted(existing_sources.union(discovered_sources))
                existing["connection_type"] = normalized.get("connection_type", existing.get("connection_type", "Unknown"))
                existing["detection_confidence"] = max(
                    existing.get("detection_confidence", 0),
                    normalized.get("detection_confidence", 0)
                )
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
            target_subnets = self._get_effective_scan_subnets()
            discovered = []
            timeout_per_subnet = max(8, int(SMART_SCAN_TIMEOUT / max(1, len(target_subnets))))
            for subnet in target_subnets:
                cmd = ["nmap", "-sn", "-n", "--max-retries", "1", subnet]
                output = subprocess.check_output(cmd, timeout=timeout_per_subnet).decode('utf-8', errors='ignore')
                discovered.extend(self.parse_nmap_output(output))
            return discovered
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
            return self.parse_arp_output(output, source="arp")
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
                    "status": "ACTIVE",
                    "scan_sources": ["nmap"]
                }
            elif 'MAC Address:' in line:
                mac_match = re.search(r'([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', line)
                if mac_match:
                    current_device["mac"] = mac_match.group(1).replace('-', ':').upper()
        if current_device:
            devices.append(current_device)
        return devices

    def parse_arp_output(self, output, source="arp"):
        devices = []
        # Regex for IP and MAC (generic enough for both OS)
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        mac_pattern = r'([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})'
        
        lines = output.split('\n')
        for line in lines:
            ips = re.findall(ip_pattern, line)
            macs = re.findall(mac_pattern, line)
            if ips and macs:
                ip = ips[0]
                mac = macs[0].replace('-', ':').upper()
                if not self._is_usable_host_ip(ip):
                    continue
                if not self._is_in_hotspot_network(ip):
                    continue
                if not self._is_usable_host_mac(mac):
                    continue
                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "name": self._resolve_hostname(ip),
                    "role": "Guest",
                    "bandwidth_limit": 5,
                    "status": "ACTIVE",
                    "scan_sources": [source]
                })
        return devices

    def scan_network_smart(self):
        logger.info("Running SMART network scan (multi-source)...")
        started_at = time.time()
        scan_subnets = self._get_effective_scan_subnets()

        sources = []
        if IS_LINUX:
            sources.append(self.scan_network_nmap())
        else:
            sources.append(self.scan_network_arp())

        sources.append(self._scan_network_neighbors())
        sources.append(self._ping_sweep())

        combined = []
        for source_devices in sources:
            combined.extend(source_devices or [])

        merged = {}
        for entry in combined:
            normalized = self._normalize_device(entry)
            ip = normalized.get("ip")
            if not ip or not self._is_usable_host_ip(ip):
                continue

            if ip not in merged:
                merged[ip] = normalized
                continue

            existing = merged[ip]

            if normalized.get("mac") and normalized.get("mac") != "00:00:00:00:00:00":
                existing["mac"] = normalized.get("mac")
            if normalized.get("name") and normalized.get("name") != "Unknown Device":
                existing["name"] = normalized.get("name")

            existing["scan_sources"] = sorted(set(existing.get("scan_sources", [])).union(set(normalized.get("scan_sources", []))))
            existing["connection_type"] = self._infer_connection_type(
                existing.get("name"), existing.get("mac"), existing.get("scan_sources", [])
            )
            existing["detection_confidence"] = self._calculate_confidence(existing)

        discovered = list(merged.values())
        logger.info(f"SMART scan discovered {len(discovered)} device(s)")
        self._record_scan_details("smart", scan_subnets, discovered)
        self._set_scan_duration(started_at)
        return discovered

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

        if not self._is_in_hotspot_network(ip):
            return {"status": "error", "message": "IP is outside hotspot subnet"}

        is_reachable = self._ping_ip(ip)
        existing = next((device for device in self.devices if device.get("ip") == ip), None)

        if existing:
            existing["status"] = "ACTIVE" if is_reachable else existing.get("status", "INACTIVE")
            existing.setdefault("device_type", self._infer_device_type(existing.get("name", "Unknown Device"), existing.get("ip")))
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

    def add_or_update_manual_user(self, ip, name=None, role="Guest"):
        if not ip:
            return {"status": "error", "message": "IP is required"}

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"status": "error", "message": "Invalid IP format"}

        if not self._is_in_hotspot_network(ip):
            return {"status": "error", "message": "IP is outside hotspot subnet"}

        if not self._is_usable_host_ip(ip):
            return {"status": "error", "message": "Unusable IP (broadcast/multicast/reserved)"}

        valid_roles = {"Admin": 100, "Teacher": 50, "Student": 10, "Guest": 5}
        chosen_role = role if role in valid_roles else "Guest"

        is_reachable = self._ping_ip(ip)
        existing = next((device for device in self.devices if device.get("ip") == ip), None)
        target_name = (name or "").strip()

        if existing:
            if target_name:
                existing["name"] = target_name
            elif existing.get("name") in ["Unknown Device", "", f"Manual-{ip}"]:
                existing["name"] = self._resolve_hostname(ip)

            existing["role"] = chosen_role
            existing["bandwidth_limit"] = valid_roles[chosen_role]
            existing["status"] = "ACTIVE" if is_reachable else existing.get("status", "INACTIVE")
            existing["device_type"] = self._infer_device_type(existing.get("name"), ip)
            self.devices = self._sanitize_devices(self.devices)
            self.save_devices()
            return {
                "status": "success",
                "reachable": is_reachable,
                "device": existing,
                "message": "Manual user IP updated"
            }

        default_name = target_name or self._resolve_hostname(ip)
        if not default_name or default_name == "Unknown Device":
            default_name = f"Manual-{ip}"

        device = self._normalize_device({
            "ip": ip,
            "name": default_name,
            "role": chosen_role,
            "bandwidth_limit": valid_roles[chosen_role],
            "status": "ACTIVE" if is_reachable else "INACTIVE"
        })
        self.devices.append(device)
        self.devices = self._sanitize_devices(self.devices)
        self.save_devices()
        return {
            "status": "success",
            "reachable": is_reachable,
            "device": device,
            "message": "Manual user IP added"
        }

    def update_device_list(self, scan_mode="standard"):
        """
        Discovers new devices and updates the device database.
        """
        started_at = time.time()
        scan_subnets = self._get_effective_scan_subnets()
        use_smart = str(scan_mode).lower() == "smart"
        discovered = self.scan_network_smart() if use_smart else (self.scan_network_nmap() if IS_LINUX else self.scan_network_arp())

        self._merge_discovered(discovered)
        self.devices = self._sanitize_devices(self.devices)
        self._record_scan_details("smart" if use_smart else "standard", scan_subnets, discovered)
        self._set_scan_duration(started_at)
        
        self.save_devices()
        return self.devices

    def save_devices(self):
        try:
            with open(DEVICES_FILE, 'w') as f:
                json.dump(self.devices, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save devices: {e}")

scanner = NetworkScanner()
