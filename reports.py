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

    def _pdf_escape(self, value):
        text = str(value or "")
        return text.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')

    def _build_simple_pdf(self, lines):
        page_height = 792
        left = 40
        top = 760
        line_height = 14

        content_chunks = []
        current_y = top

        for line in lines:
            if current_y < 60:
                content_chunks.append("ET\nendstream")
                content_chunks.append("<PAGE_BREAK>")
                content_chunks.append("stream\nBT\n/F1 10 Tf")
                current_y = top

            safe_line = self._pdf_escape(line)
            content_chunks.append(f"{left} {current_y} Td ({safe_line}) Tj")
            content_chunks.append(f"{-left} {-current_y} Td")
            current_y -= line_height

        stream_blocks = []
        block_lines = []
        for chunk in content_chunks:
            if chunk == "<PAGE_BREAK>":
                if block_lines:
                    stream_blocks.append("\n".join(block_lines))
                block_lines = []
                continue
            block_lines.append(chunk)
        if block_lines:
            stream_blocks.append("\n".join(block_lines))

        objects = []
        objects.append("<< /Type /Catalog /Pages 2 0 R >>")

        page_ids = []
        next_object_id = 3
        for _ in stream_blocks:
            page_ids.append(next_object_id)
            next_object_id += 2

        kids = " ".join([f"{obj_id} 0 R" for obj_id in page_ids])
        objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>")

        for page_id, stream_text in zip(page_ids, stream_blocks):
            content_id = page_id + 1
            objects.append(
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 {page_height}] /Resources << /Font << /F1 {next_object_id} 0 R >> >> /Contents {content_id} 0 R >>"
            )
            stream_body = f"BT\n/F1 10 Tf\n{stream_text}\nET"
            objects.append(f"<< /Length {len(stream_body.encode('latin-1', errors='ignore'))} >>\nstream\n{stream_body}\nendstream")

        objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

        pdf_parts = ["%PDF-1.4\n"]
        offsets = [0]
        for index, obj in enumerate(objects, start=1):
            offsets.append(sum(len(part.encode('latin-1', errors='ignore')) for part in pdf_parts))
            pdf_parts.append(f"{index} 0 obj\n{obj}\nendobj\n")

        xref_start = sum(len(part.encode('latin-1', errors='ignore')) for part in pdf_parts)
        xref_lines = [f"xref\n0 {len(objects) + 1}\n", "0000000000 65535 f \n"]
        for offset in offsets[1:]:
            xref_lines.append(f"{offset:010d} 00000 n \n")

        trailer = (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_start}\n%%EOF"
        )
        pdf_parts.extend(xref_lines)
        pdf_parts.append(trailer)
        return "".join(pdf_parts).encode('latin-1', errors='ignore')

    def generate_pdf_report(self, history_data, devices=None, filename=None):
        if not filename:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"usage_report_{timestamp}.pdf"

        filepath = os.path.join(REPORTS_DIR, filename)
        device_map = {item.get("ip"): item for item in (devices or []) if item.get("ip")}

        lines = []
        lines.append("SmartNet Usage Report")
        lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("-")

        total_rows = 0
        total_usage = 0.0
        for ip, history in (history_data or {}).items():
            total_rows += len(history)
            total_usage += sum(float(entry.get("val", 0.0)) for entry in history)

        lines.append(f"Devices in report: {len(history_data or {})}")
        lines.append(f"Total samples: {total_rows}")
        lines.append(f"Total observed usage (sum): {total_usage:.2f} Mbps")
        lines.append("-")
        lines.append("Device Summary")

        if not history_data:
            lines.append("No usage history available for connected devices.")
        else:
            for ip, history in sorted(history_data.items(), key=lambda item: item[0]):
                device = device_map.get(ip, {})
                name = device.get("name") or f"Device-{ip.split('.')[-1]}"
                role = device.get("role", "Guest")
                samples = len(history)
                avg = (sum(float(entry.get("val", 0.0)) for entry in history) / samples) if samples else 0.0
                peak = max((float(entry.get("val", 0.0)) for entry in history), default=0.0)
                lines.append(f"{name} | {ip} | Role: {role} | Samples: {samples} | Avg: {avg:.2f} | Peak: {peak:.2f}")

            lines.append("-")
            lines.append("Detailed Samples")
            lines.append("Name | IP | Timestamp | Usage (Mbps)")
            for ip, history in sorted(history_data.items(), key=lambda item: item[0]):
                device = device_map.get(ip, {})
                name = device.get("name") or f"Device-{ip.split('.')[-1]}"
                for entry in history:
                    lines.append(f"{name} | {ip} | {entry.get('time', '')} | {float(entry.get('val', 0.0)):.2f}")

        try:
            pdf_bytes = self._build_simple_pdf(lines)
            with open(filepath, 'wb') as f:
                f.write(pdf_bytes)

            logger.info(f"PDF_REPORT_GENERATED: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"PDF_REPORT_FAILURE: {e}")
            return None

report_gen = ReportGenerator()
