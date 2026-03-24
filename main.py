import time
import threading
import uvicorn
import logging
from scanner import scan_network, get_default_subnet
from monitor import monitor
import api

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Main")

SUBNET = get_default_subnet()
known_devices = {}

def alert_system(devices):
    global known_devices
    
    current_ips = set([d['ip'] for d in devices])
    known_ips = set(known_devices.keys())
    
    # Check for new devices
    new_ips = current_ips - known_ips
    for ip in new_ips:
        device = next(d for d in devices if d['ip'] == ip)
        logger.info(f"[ALERT] New Device Connected -> IP: {device['ip']}, MAC: {device['mac']}, Name: {device['name']}")
        if device['name'] in ["Unknown", "Unknown Device"]:
            logger.warning(f"[ALERT] Unknown device detected at {device['ip']}!")
            
    # Check for disconnected devices
    disc_ips = known_ips - current_ips
    for ip in disc_ips:
        logger.info(f"[ALERT] Device Disconnected -> IP: {ip}, Name: {known_devices[ip]['name']}")
        
    # Update known devices state
    known_devices = {d['ip']: d for d in devices}

def background_loop():
    logger.info(f"Starting auto-refresh loop on subnet {SUBNET}...")
    while True:
        try:
            # 1. Scan network
            current_devices = scan_network(SUBNET)
            
            # 2. Trigger alerts
            alert_system(current_devices)
            
            # 3. Update API state
            api.devices_state = current_devices
            
            # 4. Get bandwidth usage
            current_usage = monitor.get_usage()
            
            # 5. Format usage for API
            formatted_usage = {}
            for ip, bytes_used in current_usage.items():
                if ip in known_devices:
                    formatted_usage[ip] = bytes_used
                    
            api.usage_state = formatted_usage
            
        except Exception as e:
            logger.error(f"Background Loop error: {e}")
            
        # Rescan every 5-10 seconds
        time.sleep(5)

if __name__ == "__main__":
    logger.info("Initializing Real-Time Hotspot Monitor...")
    
    # Start Bandwidth Monitor
    monitor.start()
    
    # Start Background Loop
    loop_thread = threading.Thread(target=background_loop, daemon=True)
    loop_thread.start()
    
    # Run API server
    logger.info("Starting backend API on 0.0.0.0:8000")
    uvicorn.run(api.app, host="0.0.0.0", port=8000, log_level="warning")
