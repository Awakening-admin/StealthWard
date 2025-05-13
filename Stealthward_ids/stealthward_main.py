import sys
import os
import threading
import time
import json
import hashlib
from datetime import datetime

from stealthward_live_traffic import StealthWardLiveIDS
from stealthward_pcap_analyzer import PCAPAnalyzer
from stealthward_admin_log_analyzer import AdminLogAnalyzer
from stealthward_endpoint_log_analyzer import EndpointLogAnalyzer
from pystats import StatsGenerator

class StealthWardIDS:
    def __init__(self):
        # Initialize all analyzers
        self.live_analyzer = StealthWardLiveIDS()
        self.pcap_analyzer = PCAPAnalyzer()
        self.admin_log_analyzer = AdminLogAnalyzer()
        self.endpoint_log_analyzer = EndpointLogAnalyzer()
        self.running = False
        
        # File monitoring configuration
        self.monitored_files = [
            '/home/robot/edr_server/network_threats.json',
            '/home/robot/edr_server/ids_admin_log_alerts.json',
            '/home/robot/edr_server/ids_pcap_alerts.json',
            '/home/robot/edr_server/threats.json'
        ]
        self.file_hashes = {}
        
        # Initialize stats generator if available
        self.stats_enabled = False
        try:
            self.stats_generator = StatsGenerator()
            self.stats_enabled = True
        except ImportError:
            print("[!] pystats module not found, continuing without statistics")

    def _file_hash(self, filepath):
        """Generate MD5 hash of a file's contents"""
        if not os.path.exists(filepath):
            return None
        hasher = hashlib.md5()
        with open(filepath, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()

    def _check_file_changes(self):
        """Check if any monitored files have changed"""
        changes_detected = False
        for filepath in self.monitored_files:
            current_hash = self._file_hash(filepath)
            if current_hash is None:
                continue
                
            if filepath not in self.file_hashes:
                self.file_hashes[filepath] = current_hash
                changes_detected = True
            elif self.file_hashes[filepath] != current_hash:
                self.file_hashes[filepath] = current_hash
                changes_detected = True
                
        return changes_detected

    def start_live_analysis(self):
        print("[*] Starting live traffic analysis...")
        self.live_analyzer.start()

    def start_pcap_analysis(self):
        print("[*] Starting periodic PCAP analysis...")
        while self.running:
            try:
                self.pcap_analyzer.analyze_pcaps()
            except Exception as e:
                print(f"[!] PCAP analysis error: {e}")
            time.sleep(60)

    def start_admin_log_analysis(self):
        print("[*] Starting admin log analysis...")
        while self.running:
            try:
                self.admin_log_analyzer.analyze_logs()
            except Exception as e:
                print(f"[!] Admin log analysis error: {e}")
            time.sleep(60)

    def start_endpoint_log_analysis(self):
        print("[*] Starting endpoint log analysis...")
        while self.running:
            try:
                self.endpoint_log_analyzer.analyze_logs()
            except Exception as e:
                print(f"[!] Endpoint log analysis error: {e}")
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

        # Start all components in separate threads
        threads = [
            threading.Thread(target=self.start_live_analysis),
            threading.Thread(target=self.start_pcap_analysis),
            threading.Thread(target=self.start_admin_log_analysis),
            threading.Thread(target=self.start_endpoint_log_analysis)
        ]

        # Add stats monitoring if enabled
        if self.stats_enabled:
            threads.append(threading.Thread(target=self.start_stats_monitoring))

        # Start all threads
        for t in threads:
            t.daemon = True
            t.start()

        try:
            # Main loop
            while self.running:
                time.sleep(1)
                
                # Periodically print status
                if int(time.time()) % 300 == 0:  # Every 5 minutes
                    print("[*] StealthWard IDS running...")
                    
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        print("\n[*] Stopping StealthWard IDS...")
        self.live_analyzer.stop()
        
        # Give threads time to clean up
        time.sleep(2)
        print("[*] All components stopped")

if __name__ == "__main__":
    print("[*] Starting StealthWard IDS...")
    print(f"[*] Startup time: {datetime.now().isoformat()}")
    
    ids = StealthWardIDS()
    try:
        ids.start()
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        ids.stop()
        sys.exit(1)
