#!/home/robot/edr_processor/venv/bin/python3
import threading
import time
import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.append(project_root)

from src.suricata import continuous_suricata_analysis, periodic_pcap_threat_detection
from src.clamav import periodic_threat_detection, periodic_clamav_scan
from src.pystats import start_stats_monitoring
from src.utils import logger
def main():
    # Start all services in separate threads
    threads = [
        threading.Thread(target=continuous_suricata_analysis, daemon=True),
        threading.Thread(target=periodic_pcap_threat_detection, daemon=True),
        threading.Thread(target=periodic_threat_detection, daemon=True),
        threading.Thread(target=periodic_clamav_scan, daemon=True),
        threading.Thread(target=start_stats_monitoring, daemon=True)
    ]

    for thread in threads:
        thread.start()

    logger.info("All EDR processors started successfully")

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down EDR processors...")

if __name__ == "__main__":
    main()
