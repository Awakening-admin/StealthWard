import os
import json
import pyshark
import re
import multiprocessing
from datetime import datetime
from collections import defaultdict

class PCAPAnalyzer:
    def __init__(self):
        self.pcap_dir = "/home/robot/edr_server/pcap_files"
        self.output_file = "/home/robot/edr_server/ids_pcap_alerts.json"
        self.rules_dir = "/home/robot/edr_server/IDS_RULES_PCAP"
        self.rules = {}
        self.alert_count = 0
        self.packet_count = 0
        self.max_pcap_time = 300  # 5 minute timeout per PCAP
        self.seen_alerts = set()  # Track seen alerts
        self.load_rules()
        self.load_existing_alerts()

    def load_rules(self):
        """Load only essential rules for faster processing"""
        essential_rules = [
            'emerging-exploit.rules',
            'emerging-malware.rules',
            'emerging-attack_response.rules',
            'compromised.rules',
            'tor.rules',
            'ciarmy.rules',
            'emerging-current_events.rules',
            'emerging-dos.rules',
            'emerging-shellcode.rules',
            'emerging-scan.rules'
        ]

        print("[*] Loading essential detection rules...")
        if not os.path.exists(self.rules_dir):
            print(f"[!] Rules directory not found: {self.rules_dir}")
            return

        try:
            for rule_file in essential_rules:
                path = os.path.join(self.rules_dir, rule_file)
                if os.path.exists(path):
                    print(f"[*] Loading rules from: {rule_file}")
                    with open(path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            if 'alert' in line:
                                parts = [p.strip() for p in line.split(';')]
                                if len(parts) < 5:
                                    continue

                                rule = {
                                    'action': parts[0],
                                    'protocol': parts[1] if len(parts) > 1 else '',
                                    'source': parts[2] if len(parts) > 2 else '',
                                    'destination': parts[3] if len(parts) > 3 else '',
                                    'message': parts[4].split('(')[0] if len(parts) > 4 else '',
                                    'content': self.extract_content(line),
                                    'sid': self.extract_sid(line)
                                }
                                if rule['sid']:
                                    self.rules[rule['sid']] = rule
            print(f"[+] Loaded {len(self.rules)} essential rules")
        except Exception as e:
            print(f"[!] Error loading rules: {str(e)}")

    def extract_content(self, rule_line):
        """Extract content patterns from rule line"""
        content_matches = []
        try:
            # Look for content:"..." patterns
            contents = re.findall(r'content:"([^"]+)"', rule_line)
            if contents:
                content_matches.extend(contents)

            # Look for pcre:/.../ patterns
            pcre = re.search(r'pcre:"([^"]+)"', rule_line)
            if pcre:
                content_matches.append(f"PCRE:{pcre.group(1)}")
        except Exception:
            pass
        return content_matches

    def extract_sid(self, rule_line):
        """Extract SID from rule line"""
        try:
            sid_part = [p for p in rule_line.split(';') if 'sid:' in p.lower()]
            if sid_part:
                return sid_part[0].split(':')[1].strip(';').strip()
        except Exception as e:
            print(f"[!] Error extracting SID: {str(e)}")
        return None

    def load_existing_alerts(self):
        """Load existing alerts to prevent duplicates"""
        if os.path.exists(self.output_file):
            try:
                with open(self.output_file, 'r') as f:
                    for alert in json.load(f):
                        self.seen_alerts.add(self._alert_signature(alert))
            except Exception as e:
                print(f"[!] Error loading existing alerts: {str(e)}")

    def _alert_signature(self, alert):
        """Create unique signature for an alert"""
        return (alert['source_ip'],
                alert['dest_ip'],
                alert['rule_sid'],
                alert['pcap_info']['src_port'],
                alert['pcap_info']['dst_port'],
                alert['protocol'])

    def analyze_pcaps(self):
        """Analyze all PCAP files with timeout handling"""
        if not os.path.exists(self.pcap_dir):
            print(f"[!] PCAP directory not found: {self.pcap_dir}")
            return False

        print("[*] Starting optimized PCAP analysis...")
        all_alerts = []
        processed_files = 0

        try:
            for filename in sorted(os.listdir(self.pcap_dir)):
                if filename.endswith('.pcap'):
                    filepath = os.path.join(self.pcap_dir, filename)
                    file_alerts = self.analyze_pcap_with_timeout(filepath)
                    if file_alerts:
                        all_alerts.extend(file_alerts)
                    processed_files += 1

            print(f"[+] Processed {processed_files} PCAP files")
            print(f"[+] Total packets analyzed: {self.packet_count}")
            print(f"[+] Total alerts detected: {self.alert_count}")

            if all_alerts:
                self.save_alerts(all_alerts)
                return True

            print("[*] No new alerts detected in any PCAP files")
            return True

        except Exception as e:
            print(f"[!] PCAP analysis failed: {str(e)}")
            return False

    def analyze_pcap_with_timeout(self, pcap_file):
        """Analyze PCAP with timeout using multiprocessing"""
        def worker(pcap_file, queue):
            try:
                alerts = self._analyze_pcap(pcap_file)
                queue.put(alerts)
            except Exception as e:
                queue.put([])
                print(f"[!] PCAP analysis failed: {str(e)}")

        queue = multiprocessing.Queue()
        p = multiprocessing.Process(target=worker, args=(pcap_file, queue))
        p.start()
        p.join(timeout=self.max_pcap_time)

        if p.is_alive():
            p.terminate()
            p.join()
            print(f"[!] Timeout analyzing {os.path.basename(pcap_file)} after {self.max_pcap_time} seconds")
            return []

        return queue.get() if not queue.empty() else []

    def _analyze_pcap(self, pcap_file):
        """Core PCAP analysis without timeout"""
        alerts = []
        if not os.path.exists(pcap_file):
            print(f"[!] PCAP file not found: {pcap_file}")
            return alerts

        print(f"[*] Analyzing PCAP file: {os.path.basename(pcap_file)}")
        try:
            cap = pyshark.FileCapture(
                pcap_file,
                display_filter='tcp or udp or icmp',
                use_json=True,
                only_summaries=False,
                debug=False
            )

            file_packet_count = 0
            file_alert_count = 0
            last_update = 0

            for pkt in cap:
                file_packet_count += 1
                self.packet_count += 1

                try:
                    alert = self.check_packet(pkt)
                    if alert:
                        sig = self._alert_signature(alert)
                        if sig not in self.seen_alerts:
                            alerts.append(alert)
                            self.seen_alerts.add(sig)
                            file_alert_count += 1
                            self.alert_count += 1

                        # Periodic status update every 1000 packets
                        if file_packet_count - last_update >= 1000:
                            print(f"[*] Processed {file_packet_count} packets, found {file_alert_count} alerts")
                            last_update = file_packet_count

                except Exception as e:
                    continue  # Skip packet errors

            cap.close()
            print(f"[+] Analyzed {file_packet_count} packets, found {file_alert_count} alerts")

        except Exception as e:
            print(f"[!] PCAP analysis error: {str(e)}")

        return alerts

    def check_packet(self, pkt):
        """Check packet against loaded rules"""
        if not self.rules:
            return None

        try:
            # Fast protocol check first
            protocol = getattr(pkt, 'highest_layer', '').lower()
            if not protocol:
                return None

            # Get basic packet info
            src_ip = getattr(pkt.ip, 'src', 'N/A') if hasattr(pkt, 'ip') else 'N/A'
            dst_ip = getattr(pkt.ip, 'dst', 'N/A') if hasattr(pkt, 'ip') else 'N/A'

            # Get transport layer info
            src_port = 'N/A'
            dst_port = 'N/A'
            transport_layer = getattr(pkt, 'transport_layer', None)
            if transport_layer:
                transport = getattr(pkt, transport_layer)
                src_port = getattr(transport, 'srcport', 'N/A')
                dst_port = getattr(transport, 'dstport', 'N/A')

            # Check against each rule
            for sid, rule in self.rules.items():
                if self.match_rule(pkt, rule):
                    return {
                        'timestamp': getattr(pkt, 'sniff_time', datetime.now()).isoformat(),
                        'source_ip': src_ip,
                        'dest_ip': dst_ip,
                        'protocol': protocol,
                        'rule_sid': sid,
                        'rule_msg': rule['message'],
                        'severity': 'high',
                        'pcap_info': {
                            'src_port': src_port,
                            'dst_port': dst_port
                        }
                    }
        except Exception as e:
            print(f"[!] Packet check error: {str(e)}")
        return None

    def match_rule(self, pkt, rule):
        """Optimized rule matching"""
        try:
            # Protocol check
            protocol = getattr(pkt, 'highest_layer', '').lower()
            if rule['protocol'].lower() not in protocol:
                return False

            # Content pattern matching first (most specific)
            if rule.get('content'):
                packet_text = str(pkt).lower()
                for content in rule['content']:
                    if content.startswith('PCRE:'):
                        if re.search(content[5:], packet_text, re.IGNORECASE):
                            return True
                    elif content.lower() in packet_text:
                        return True

            # Protocol-specific checks
            if 'dns' in rule['message'].lower() and hasattr(pkt, 'dns'):
                if hasattr(pkt.dns, 'qry_name'):
                    for content in rule.get('content', []):
                        if content.lower() in pkt.dns.qry_name.lower():
                            return True

            if 'http' in rule['message'].lower() and hasattr(pkt, 'http'):
                http_uri = getattr(pkt.http, 'request_uri', '')
                http_host = getattr(pkt.http, 'host', '')
                http_data = f"{http_uri} {http_host}".lower()
                for content in rule.get('content', []):
                    if content.lower() in http_data:
                        return True

            return False
        except Exception as e:
            print(f"[!] Rule matching error: {str(e)}")
            return False

    def save_alerts(self, alerts):
        """Save alerts with duplicate prevention"""
        if not alerts:
            print("[*] No new alerts to save")
            return False

        try:
            # Read existing alerts
            existing_alerts = []
            if os.path.exists(self.output_file):
                with open(self.output_file, 'r') as f:
                    existing_alerts = json.load(f)

            # Append new alerts
            existing_alerts.extend(alerts)

            # Save back to file
            temp_file = self.output_file + '.tmp'
            with open(temp_file, 'w') as f:
                json.dump(existing_alerts, f, indent=2, ensure_ascii=False)
            os.replace(temp_file, self.output_file)

            print(f"[+] Saved {len(alerts)} new alerts to {self.output_file}")
            return True
        except Exception as e:
            print(f"[!] Failed to save alerts: {str(e)}")
            try:
                fallback_file = "/tmp/ids_pcap_alerts.json"
                with open(fallback_file, 'w') as f:
                    json.dump(alerts, f, indent=2)
                print(f"[!] Saved alerts to fallback location: {fallback_file}")
                return True
            except Exception as fallback_e:
                print(f"[!!] Failed to save alerts anywhere: {str(fallback_e)}")
                return False
