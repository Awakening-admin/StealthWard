from scapy.all import sniff
import threading
import time

class StealthWardLiveIDS:
    def __init__(self):
        from stealthward_functions import ThreatDetector
        self.detector = ThreatDetector()
        self.running = False

    def start_sniffing(self):
        print("[*] Sniffing live network traffic...")
        sniff(filter="tcp or udp or icmp", prn=self.detector.packet_handler, store=0)
    
    def start(self):
        self.running = True
        self.sniff_thread = threading.Thread(target=self.start_sniffing)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
    
    def stop(self):
        self.running = False
        if hasattr(self, 'sniff_thread'):
            self.sniff_thread.join(timeout=2)
