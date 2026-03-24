import threading
import logging
from scapy.all import sniff, IP
from collections import defaultdict

logger = logging.getLogger("Monitor")

class BandwidthMonitor:
    def __init__(self):
        self.usage_records = defaultdict(int) # Tracks cumulative bytes per IP
        self.lock = threading.Lock()
        self.is_running = False
        self.sniffer_thread = None

    def _packet_callback(self, packet):
        """Callback to process each intercepted packet."""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            pkt_len = len(packet)

            with self.lock:
                self.usage_records[src_ip] += pkt_len
                self.usage_records[dst_ip] += pkt_len

    def _start_sniffing(self):
        """Internal sniffing loop using scapy."""
        logger.info("Starting packet sniffing for bandwidth tracking...")
        try:
            # store=False ensures we don't leak memory
            sniff(prn=self._packet_callback, store=False, stop_filter=lambda x: not self.is_running)
        except PermissionError:
            logger.error("Permission denied. Run with Admin/Root privileges to capture packets.")
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
        logger.info("Sniffing stopped.")

    def start(self):
        """Starts the bandwidth monitor in a background thread."""
        if not self.is_running:
            self.is_running = True
            self.sniffer_thread = threading.Thread(target=self._start_sniffing, daemon=True)
            self.sniffer_thread.start()

    def stop(self):
        """Stops the bandwidth monitor."""
        self.is_running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)

    def get_usage(self):
        """Retrieve a copy of the cumulative usage dictionary (IP -> Bytes)."""
        with self.lock:
            return dict(self.usage_records)

monitor = BandwidthMonitor()
