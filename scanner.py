import socket
import platform
import subprocess
import re
from scapy.all import ARP, Ether, srp
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Scanner")

def get_default_subnet():
    """Returns the default subnet to scan. Uses 192.168.43.1/24 as mobile hotspot default."""
    return "192.168.43.1/24"

def resolve_hostname(ip):
    """Attempt to resolve the hostname of a given IP address."""
    try:
        # Try standard reverse dns
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        # Fallback to NetBIOS or ping -a on windows
        if platform.system().lower() == "windows":
            try:
                # Use ping -a to resolve hostname on windows
                output = subprocess.check_output(f"ping -a -n 1 -w 200 {ip}", shell=True).decode(errors='ignore')
                match = re.search(r'Pinging\s+(.+?)\s+\[', output)
                if match:
                    name = match.group(1).strip()
                    if name and name != ip:
                        return name
            except Exception:
                pass
        return "Unknown"

def fallback_scan():
    """Fallback scanner using the system 'arp' command."""
    devices = []
    try:
        output = subprocess.check_output(['arp', '-a']).decode(errors='ignore')
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        mac_pattern = r'([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})'
        
        for line in output.splitlines():
            ips = re.findall(ip_pattern, line)
            macs = re.findall(mac_pattern, line)
            if ips and macs:
                ip = ips[0]
                mac = macs[0].replace('-', ':').upper()
                
                # Filter out multicast/broadcast
                if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255"):
                    continue
                if mac.startswith("01:00:5E") or mac == "FF:FF:FF:FF:FF:FF":
                    continue
                    
                name = resolve_hostname(ip)
                devices.append({'ip': ip, 'mac': mac, 'name': name})
    except Exception as e:
        logger.error(f"Fallback scan failed: {e}")
    return devices

def scan_network(subnet):
    """
    Scans the given subnet using ARP requests and returns a list of discovered devices.
    Falls back to system ARP if scapy is unavailable or fails (requires admin).
    """
    logger.debug(f"Scanning subnet: {subnet}")
    devices = []
    try:
        # Create ARP packet
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        # Send packet and capture responses
        result, _ = srp(packet, timeout=2, verbose=0, multi=True)
        
        for sent, received in result:
            ip = received.psrc
            mac = received.hwsrc.upper()
            
            # Simple hostname resolution
            name = resolve_hostname(ip)
            devices.append({'ip': ip, 'mac': mac, 'name': name})
            
        if not devices:
            devices = fallback_scan()
            
    except PermissionError:
        logger.warning("Permission denied for scapy ARP scan. Falling back to system 'arp'.")
        devices = fallback_scan()
    except Exception as e:
        logger.warning(f"Error during ARP scan: {e}. Falling back to system 'arp'.")
        devices = fallback_scan()
        
    return devices

if __name__ == "__main__":
    subnet = get_default_subnet()
    res = scan_network(subnet)
    print(f"Discovered {len(res)} devices:")
    for dev in res:
        print(dev)
