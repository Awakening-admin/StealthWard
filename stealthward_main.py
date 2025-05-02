from stealthward_live_traffic import StealthWardLiveIDS
from stealthward_pcap_analyzer import PCAPAnalyzer
from stealthward_admin_log_analyzer import AdminLogAnalyzer
from stealthward_endpoint_log_analyzer import EndpointLogAnalyzer
import threading
import time
import os

class StealthWardIDS:
    def __init__(self):
        self.live_analyzer = StealthWardLiveIDS()
        self.pcap_analyzer = PCAPAnalyzer()
        self.admin_log_analyzer = AdminLogAnalyzer()
        self.endpoint_log_analyzer = EndpointLogAnalyzer()
        self.running = False
        
        # Lightweight stats integration
        self.stats_enabled = False
        try:
            from pystats import StatsGenerator
            self.stats_generator = StatsGenerator()
            self.stats_enabled = True
        except ImportError:
            print("[!] pystats module not found, continuing without statistics")

    def start_live_analysis(self):
        print("[*] Starting live traffic analysis...")
        self.live_analyzer.start()

    def start_pcap_analysis(self):
        print("[*] Starting periodic PCAP analysis...")
        while self.running:
            self.pcap_analyzer.analyze_pcaps()
            time.sleep(60)

    def start_admin_log_analysis(self):
        print("[*] Starting admin log analysis...")
        while self.running:
            self.admin_log_analyzer.analyze_logs()
            time.sleep(60)

    def start_endpoint_log_analysis(self):
        print("[*] Starting endpoint log analysis...")
        while self.running:
            self.endpoint_log_analyzer.analyze_logs()
            time.sleep(60)

    def start_stats_monitoring(self):
        """Non-blocking stats generation"""
        if not self.stats_enabled:
            return
            
        print("[*] Starting background stats collection...")
        while self.running:
            try:
                self.stats_generator.generate_all_stats()
            except Exception as e:
                print(f"[!] Stats generation error: {e}")
            time.sleep(300)  # Generate stats every 5 minutes

    def start(self):
        self.running = True

        # Start all components
        threads = [
            threading.Thread(target=self.start_live_analysis),
            threading.Thread(target=self.start_pcap_analysis),
            threading.Thread(target=self.start_admin_log_analysis),
            threading.Thread(target=self.start_endpoint_log_analysis),
            threading.Thread(target=self.start_stats_monitoring)
        ]

        for t in threads:
            t.daemon = True
            t.start()

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        print("\n[*] Stopping StealthWard IDS...")
        self.live_analyzer.stop()

if __name__ == "__main__":
    print("[*] Starting StealthWard IDS...")
    ids = StealthWardIDS()
    ids.start()