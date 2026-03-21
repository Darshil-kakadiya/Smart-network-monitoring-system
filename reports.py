import csv
import os
import time
from logger import logger

REPORTS_DIR = 'reports'

class ReportGenerator:
    def __init__(self):
        if not os.path.exists(REPORTS_DIR):
            try:
                os.makedirs(REPORTS_DIR)
            except Exception:
                pass

    def generate_csv_report(self, history_data, filename=None):
        """
        Generates a CSV report from the usage history.
        history_data: { ip: [ {time, val}, ... ] }
        """
        if not filename:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"usage_report_{timestamp}.csv"
        
        filepath = os.path.join(REPORTS_DIR, filename)
        
        try:
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IP Address', 'Timestamp', 'Usage (Mbps)'])
                
                for ip, history in history_data.items():
                    for entry in history:
                        writer.writerow([ip, entry['time'], entry['val']])
            
            logger.info(f"REPORT_GENERATED: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"REPORT_FAILURE: {e}")
            return None

report_gen = ReportGenerator()
