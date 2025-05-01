from scapy.all import *
load_contrib("http")
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from collections import defaultdict
from datetime import datetime, timedelta
import threading
import json
import os
import re

# Configuration
DETECTION_RULES = {
    'ssh_bruteforce': {
        'port': 22,
        'threshold': 10,
        'window': 10
    },
    'ftp_bruteforce': {
        'port': 21,
        'threshold': 10,
        'window': 10
    },
    'icmp_flood': {
        'threshold': 30,
        'window': 10
    },
    'dns_tunneling': {
        'port': 53,
        'threshold': 100,
        'window': 60,
        'size_threshold': 512
    },
    'http_malware': {
        'port': 80,
        'patterns': [
            r'(cmd\.exe|powershell)',
            r'(union select|drop table|1=1)',
            r'(\.php\?|\.asp\?)',
            r'(eval\(|base64_decode\()'
        ]
    },
    'ransomware': {
        'patterns': [
            r'\.encrypted$',
            r'\.locked$',
            r'ransom',
            r'bitcoin payment'
        ]
    },
    'dos_attack': {
        'threshold': 1000,
        'window': 1
    }
}

THREATS_FILE = "/home/robot/edr_server/network_threats.json"
os.makedirs(os.path.dirname(THREATS_FILE), exist_ok=True)

class ThreatDetector:
    def __init__(self):
        self.ssh_attempts = defaultdict(list)
        self.ftp_attempts = defaultdict(list)
        self.icmp_flood = defaultdict(list)
        self.dns_queries = defaultdict(list)
        self.packet_counts = defaultdict(int)
        self.last_dos_check = datetime.now()
        self.lock = threading.Lock()
        self.max_threats = 100  # Max threats to keep in file

    def save_threat(self, threat_data):
        with self.lock:
            # Load existing threats
            threats = []
            if os.path.exists(THREATS_FILE):
                try:
                    with open(THREATS_FILE, 'r') as f:
                        threats = json.load(f)
                        if not isinstance(threats, list):
                            threats = []
                except Exception as e:
                    print(f"Error loading threats file: {e}")
                    threats = []

            # Add new threat
            threats.append(threat_data)

            # Keep only the most recent threats
            if len(threats) > self.max_threats:
                threats = threats[-self.max_threats:]

            # Save back to file
            try:
                with open(THREATS_FILE, 'w') as f:
                    json.dump(threats, f, indent=2)
            except Exception as e:
                print(f"Error saving threats: {e}")

    def detect_bruteforce(self, ip_attempts, ip, threshold, window, service_name):
        now = datetime.now()
        ip_attempts[ip] = [t for t in ip_attempts[ip] if now - t < timedelta(seconds=window)]
        ip_attempts[ip].append(now)
        if len(ip_attempts[ip]) >= threshold:
            threat = {
                'type': 'bruteforce',
                'service': service_name,
                'source_ip': ip,
                'attempts': len(ip_attempts[ip]),
                'timestamp': now.isoformat(),
                'severity': 'high',
                'signature': f"{service_name} brute-force attempt",
                'category': 'bruteforce'
            }
            self.save_threat(threat)
            return True
        return False

    def detect_icmp_flood(self, ip):
        now = datetime.now()
        window = DETECTION_RULES['icmp_flood']['window']
        threshold = DETECTION_RULES['icmp_flood']['threshold']

        self.icmp_flood[ip] = [t for t in self.icmp_flood[ip] if now - t < timedelta(seconds=window)]
        self.icmp_flood[ip].append(now)
        if len(self.icmp_flood[ip]) >= threshold:
            threat = {
                'type': 'icmp_flood',
                'source_ip': ip,
                'count': len(self.icmp_flood[ip]),
                'timestamp': now.isoformat(),
                'severity': 'medium',
                'signature': "ICMP flood detected",
                'category': 'flood'
            }
            self.save_threat(threat)
            return True
        return False

    def detect_dns_tunneling(self, pkt):
        if DNS in pkt and DNSQR in pkt:
            dns = pkt[DNS]
            if dns.qr == 0:  # DNS query
                src_ip = pkt[IP].src
                now = datetime.now()
                window = DETECTION_RULES['dns_tunneling']['window']
                size_threshold = DETECTION_RULES['dns_tunneling']['size_threshold']

                # Check for large DNS packets
                if len(pkt) > size_threshold:
                    threat = {
                        'type': 'dns_tunneling',
                        'source_ip': src_ip,
                        'packet_size': len(pkt),
                        'query': str(pkt[DNSQR].qname),
                        'timestamp': now.isoformat(),
                        'severity': 'high',
                        'signature': "Large DNS packet detected",
                        'category': 'tunneling'
                    }
                    self.save_threat(threat)
                    return True

                # Check for high query rate
                self.dns_queries[src_ip] = [t for t in self.dns_queries[src_ip] if now - t < timedelta(seconds=window)]
                self.dns_queries[src_ip].append(now)
                if len(self.dns_queries[src_ip]) >= DETECTION_RULES['dns_tunneling']['threshold']:
                    threat = {
                        'type': 'dns_tunneling',
                        'source_ip': src_ip,
                        'query_count': len(self.dns_queries[src_ip]),
                        'timestamp': now.isoformat(),
                        'severity': 'high',
                        'signature': "High DNS query rate detected",
                        'category': 'tunneling'
                    }
                    self.save_threat(threat)
                    return True
        return False

    def detect_http_malware(self, pkt):
        if TCP in pkt and pkt[TCP].dport == 80 and Raw in pkt:
            payload = str(pkt[Raw].load)
            for pattern in DETECTION_RULES['http_malware']['patterns']:
                if re.search(pattern, payload, re.IGNORECASE):
                    threat = {
                        'type': 'http_malware',
                        'source_ip': pkt[IP].src,
                        'destination_ip': pkt[IP].dst,
                        'payload_snippet': payload[:100],
                        'matched_pattern': pattern,
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'critical',
                        'signature': "Malicious HTTP content detected",
                        'category': 'malware'
                    }
                    self.save_threat(threat)
                    return True
        return False

    def detect_dos_attack(self, ip):
        now = datetime.now()
        window = DETECTION_RULES['dos_attack']['window']
        threshold = DETECTION_RULES['dos_attack']['threshold']

        self.packet_counts[ip] = self.packet_counts.get(ip, 0) + 1

        if (now - self.last_dos_check).total_seconds() > window:
            for ip, count in self.packet_counts.items():
                if count >= threshold:
                    threat = {
                        'type': 'dos_attack',
                        'source_ip': ip,
                        'packet_count': count,
                        'timestamp': now.isoformat(),
                        'severity': 'critical',
                        'signature': "Potential DoS attack detected",
                        'category': 'dos'
                    }
                    self.save_threat(threat)
            self.packet_counts.clear()
            self.last_dos_check = now
            return True
        return False

    def detect_ransomware(self, pkt):
        if Raw in pkt:
            payload = str(pkt[Raw].load)
            for pattern in DETECTION_RULES['ransomware']['patterns']:
                if re.search(pattern, payload, re.IGNORECASE):
                    threat = {
                        'type': 'ransomware',
                        'source_ip': pkt[IP].src if IP in pkt else 'N/A',
                        'payload_snippet': payload[:100],
                        'matched_pattern': pattern,
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'critical',
                        'signature': "Ransomware indicator detected",
                        'category': 'ransomware'
                    }
                    self.save_threat(threat)
                    return True
        return False

    def packet_handler(self, pkt):
        if IP in pkt:
            ip_src = pkt[IP].src

            # TCP-based detections
            if TCP in pkt:
                dport = pkt[TCP].dport

                # SSH brute force
                if dport == DETECTION_RULES['ssh_bruteforce']['port']:
                    self.detect_bruteforce(
                        self.ssh_attempts, ip_src,
                        DETECTION_RULES['ssh_bruteforce']['threshold'],
                        DETECTION_RULES['ssh_bruteforce']['window'],
                        "SSH"
                    )

                # FTP brute force
                elif dport == DETECTION_RULES['ftp_bruteforce']['port']:
                    self.detect_bruteforce(
                        self.ftp_attempts, ip_src,
                        DETECTION_RULES['ftp_bruteforce']['threshold'],
                        DETECTION_RULES['ftp_bruteforce']['window'],
                        "FTP"
                    )

                # HTTP malware detection
                elif dport == 80 or dport == 443:
                    self.detect_http_malware(pkt)
                    self.detect_ransomware(pkt)

            # ICMP flood detection
            elif ICMP in pkt:
                self.detect_icmp_flood(ip_src)

            # DNS tunneling detection
            elif UDP in pkt and pkt[UDP].dport == 53:
                self.detect_dns_tunneling(pkt)

            # General DoS detection
            self.detect_dos_attack(ip_src)
