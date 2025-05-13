#!/usr/bin/env python3
import os
import json
import pyshark
import regex as re
import multiprocessing
from datetime import datetime
from collections import defaultdict
import hashlib
import pickle
from pathlib import Path

class PCAPAnalyzer:
    def __init__(self):
        # Configuration paths
        self.pcap_dir = "/home/robot/edr_server/pcap_files"
        self.output_file = "/home/robot/edr_server/ids_pcap_alerts.json"
        self.processed_files_file = "/home/robot/edr_server/processed_pcaps.db"
        self.rules_dir = "/home/robot/edr_server/IDS_RULES_PCAP"
        
        # Performance tuning
        self.max_pcap_time = 300  # 5 minute timeout per PCAP
        self.packet_processing_limit = 100000  # Max packets per PCAP
        self.status_update_interval = 1000  # Packets between status updates
        
        # Tracking structures
        self.rules = {}
        self.seen_alerts = set()
        self.processed_files = self._load_processed_files()
        self.flow_tracker = FlowTracker()
        self.protocol_parsers = self._initialize_parsers()
        
        # Statistics
        self.alert_count = 0
        self.packet_count = 0
        self.processed_file_count = 0
        
        # Initialize
        self.load_rules()

    def _initialize_parsers(self):
        """Initialize protocol-specific parsers"""
        return {
            'http': HTTPParser(),
            'dns': DNSParser(),
            'tls': TLSParser(),
            'ssh': SSHParser(),
            'ftp': FTPParser(),
            'smtp': SMTPParser(),
        }

    def _load_processed_files(self):
        """Load the database of already processed files"""
        try:
            if os.path.exists(self.processed_files_file):
                with open(self.processed_files_file, 'rb') as f:
                    return pickle.load(f)
        except Exception as e:
            print(f"[!] Error loading processed files database: {str(e)}")
        return set()

    def _save_processed_files(self):
        """Save the database of processed files"""
        try:
            with open(self.processed_files_file, 'wb') as f:
                pickle.dump(self.processed_files, f)
        except Exception as e:
            print(f"[!] Error saving processed files database: {str(e)}")

    def _file_signature(self, filepath):
        """Create a unique signature for a file to detect changes"""
        stat = os.stat(filepath)
        return f"{filepath}:{stat.st_size}:{stat.st_mtime}"

    def load_rules(self):
        """Load and optimize all rules from the rules directory"""
        print("[*] Loading and optimizing detection rules...")
        
        if not os.path.exists(self.rules_dir):
            print(f"[!] Rules directory not found: {self.rules_dir}")
            return

        # Load all rule files
        rule_files = [f for f in os.listdir(self.rules_dir) if f.endswith('.rules')]
        
        for rule_file in rule_files:
            path = os.path.join(self.rules_dir, rule_file)
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        if 'alert' in line:
                            self._parse_rule_line(line)
            except Exception as e:
                print(f"[!] Error loading rules from {rule_file}: {str(e)}")

        # Post-process rules for optimization
        self._optimize_rules()
        print(f"[+] Loaded {len(self.rules)} rules")

    def _parse_rule_line(self, line):
        """Parse a single rule line and add to rules dictionary"""
        try:
            parts = [p.strip() for p in line.split(';')]
            if len(parts) < 5:
                return

            sid = self._extract_sid(line)
            if not sid:
                return

            self.rules[sid] = {
                'action': parts[0],
                'protocol': parts[1] if len(parts) > 1 else '',
                'source': parts[2] if len(parts) > 2 else '',
                'destination': parts[3] if len(parts) > 3 else '',
                'message': parts[4].split('(')[0] if len(parts) > 4 else '',
                'content': self._extract_content(line),
                'sid': sid,
                'metadata': self._extract_metadata(line)
            }
        except Exception as e:
            print(f"[!] Error parsing rule: {str(e)}")

    def _extract_content(self, rule_line):
        """Extract content patterns from rule line"""
        content_matches = []
        try:
            # Extract content:"..." patterns
            contents = re.findall(r'content:"([^"]+)"', rule_line)
            content_matches.extend(contents)
            
            # Extract pcre:"..." patterns
            pcre = re.search(r'pcre:"([^"]+)"', rule_line)
            if pcre:
                content_matches.append(f"PCRE:{pcre.group(1)}")
                
            # Extract byte_test patterns
            byte_tests = re.findall(r'byte_test:([^;]+)', rule_line)
            if byte_tests:
                content_matches.extend([f"BYTE_TEST:{bt}" for bt in byte_tests])
                
        except Exception:
            pass
        return content_matches

    def _extract_metadata(self, rule_line):
        """Extract additional metadata from rule"""
        metadata = {}
        try:
            # Extract severity
            severity = re.search(r'severity:([^;]+)', rule_line.lower())
            if severity:
                metadata['severity'] = severity.group(1).strip()
                
            # Extract reference
            reference = re.search(r'reference:([^;]+)', rule_line.lower())
            if reference:
                metadata['reference'] = reference.group(1).strip()
                
        except Exception:
            pass
        return metadata

    def _extract_sid(self, rule_line):
        """Extract SID from rule line"""
        try:
            sid_part = [p for p in rule_line.split(';') if 'sid:' in p.lower()]
            if sid_part:
                return sid_part[0].split(':')[1].strip(';').strip()
        except Exception as e:
            print(f"[!] Error extracting SID: {str(e)}")
        return None

    def _optimize_rules(self):
            """Intelligent rule optimization based on available libraries"""
            for sid, rule in self.rules.items():
                try:
                    rule['compiled_patterns'] = []
                    for content in rule.get('content', []):
                        if content.startswith('PCRE:'):
                            pattern = content[5:]
                            
                            if HAVE_REGEX:
                                # Advanced processing with regex module
                                flags = re.IGNORECASE
                                if '/s' in pattern:
                                    flags |= re.DOTALL
                                    pattern = pattern.replace('/s', '')
                                try:
                                    rule['compiled_patterns'].append(re.compile(pattern, flags))
                                except re.error:
                                    continue
                            else:
                                # Basic processing with re module
                                if any(unsupported in pattern for unsupported in ['?<', '?P=', '\\g<']):
                                    continue
                                try:
                                    rule['compiled_patterns'].append(re.compile(pattern, re.IGNORECASE))
                                except re.error:
                                    continue
                                    
                        elif not content.startswith('BYTE_TEST:'):
                            try:
                                rule['compiled_patterns'].append(re.compile(re.escape(content), re.IGNORECASE))
                            except re.error:
                                continue
                except Exception:
                    continue

    def analyze_pcaps(self):
        """Analyze all unprocessed PCAP files in the directory"""
        if not os.path.exists(self.pcap_dir):
            print(f"[!] PCAP directory not found: {self.pcap_dir}")
            return False

        print("[*] Starting PCAP analysis...")
        all_alerts = []
        processed_count = 0

        try:
            # Walk through the directory structure
            for root, _, files in os.walk(self.pcap_dir):
                for filename in files:
                    if filename.endswith('.pcap'):
                        filepath = os.path.join(root, filename)
                        file_sig = self._file_signature(filepath)
                        
                        if file_sig in self.processed_files:
                            continue  # Skip already processed files
                            
                        file_alerts = self.analyze_pcap_with_timeout(filepath)
                        if file_alerts:
                            all_alerts.extend(file_alerts)
                            
                        self.processed_files.add(file_sig)
                        processed_count += 1
                        
                        # Periodically save progress
                        if processed_count % 10 == 0:
                            self._save_processed_files()

            self._save_processed_files()
            print(f"[+] Processed {processed_count} new PCAP files")
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
                analyzer = PCAPAnalyzer()  # Create new instance for process safety
                alerts = analyzer._analyze_pcap(pcap_file)
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
        """Core PCAP analysis with DPI capabilities"""
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
                debug=False,
                keep_packets=False  # Save memory
            )

            file_packet_count = 0
            file_alert_count = 0
            last_update = 0

            for pkt in cap:
                if file_packet_count >= self.packet_processing_limit:
                    print(f"[!] Reached packet processing limit for {os.path.basename(pcap_file)}")
                    break
                    
                file_packet_count += 1
                self.packet_count += 1

                try:
                    self.flow_tracker.update(pkt)
                    alert = self.check_packet(pkt)
                    if alert:
                        sig = self._alert_signature(alert)
                        if sig not in self.seen_alerts:
                            alerts.append(alert)
                            self.seen_alerts.add(sig)
                            file_alert_count += 1
                            self.alert_count += 1

                    # Periodic status update
                    if file_packet_count - last_update >= self.status_update_interval:
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
        """Check packet against all rules with DPI"""
        if not self.rules:
            return None

        try:
            # Get basic packet info
            protocol = getattr(pkt, 'highest_layer', '').lower()
            src_ip = getattr(pkt.ip, 'src', 'N/A') if hasattr(pkt, 'ip') else 'N/A'
            dst_ip = getattr(pkt.ip, 'dst', 'N/A') if hasattr(pkt, 'ip') else 'N/A'
            src_port = 'N/A'
            dst_port = 'N/A'

            # Get transport layer info
            transport_layer = getattr(pkt, 'transport_layer', None)
            if transport_layer:
                transport = getattr(pkt, transport_layer)
                src_port = getattr(transport, 'srcport', 'N/A')
                dst_port = getattr(transport, 'dstport', 'N/A')

            # Get protocol-specific parsed data
            parsed_data = None
            if protocol in self.protocol_parsers:
                parsed_data = self.protocol_parsers[protocol].parse(pkt)

            # Check against each rule
            for sid, rule in self.rules.items():
                if self._match_rule(pkt, rule, parsed_data):
                    return {
                        'timestamp': getattr(pkt, 'sniff_time', datetime.now()).isoformat(),
                        'source_ip': src_ip,
                        'dest_ip': dst_ip,
                        'protocol': protocol,
                        'rule_sid': sid,
                        'rule_msg': rule['message'],
                        'severity': rule.get('metadata', {}).get('severity', 'medium'),
                        'pcap_info': {
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'filename': os.path.basename(pkt.filename) if hasattr(pkt, 'filename') else 'unknown'
                        },
                        'references': rule.get('metadata', {}).get('reference', '')
                    }
        except Exception as e:
            print(f"[!] Packet check error: {str(e)}")
        return None

    def _match_rule(self, pkt, rule, parsed_data=None):
        """Enhanced rule matching with DPI using standard re"""
        try:
            # Fast protocol check
            protocol = getattr(pkt, 'highest_layer', '').lower()
            if rule['protocol'].lower() not in protocol:
                return False

            # IP/Port checks
            if hasattr(pkt, 'ip'):
                if rule['source'] and not self._match_ip_port(rule['source'], pkt.ip.src, None):
                    return False
                if rule['destination'] and not self._match_ip_port(rule['destination'], pkt.ip.dst, None):
                    return False

            # Content matching with compiled patterns
            if 'compiled_patterns' in rule:
                packet_text = str(pkt).lower()
                for pattern in rule['compiled_patterns']:
                    if pattern.search(packet_text):
                        return True
                        
            # Protocol-specific content checks
            if parsed_data:
                for field in ['uri', 'host', 'user_agent', 'query']:
                    if field in parsed_data:
                        field_value = parsed_data[field].lower()
                        for content in rule.get('content', []):
                            if not content.startswith(('PCRE:', 'BYTE_TEST:')):
                                if content.lower() in field_value:
                                    return True

            return False
            
        except Exception as e:
            print(f"[!] Rule matching error: {str(e)}")
            return False

    def _match_ip_port(self, rule_pattern, ip, port):
        """Match IP and port against rule pattern"""
        # Simplified IP:port matching - can be enhanced if needed
        if 'any' in rule_pattern.lower():
            return True
        if ip in rule_pattern:
            return True
        return False

    def _alert_signature(self, alert):
        """Create unique signature for an alert"""
        return (
            alert['source_ip'],
            alert['dest_ip'],
            alert['rule_sid'],
            alert['pcap_info']['src_port'],
            alert['pcap_info']['dst_port'],
            alert['protocol'],
            alert['timestamp'][:10]  # Date only for daily deduplication
        )

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

            # Save back to file with atomic write
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

# Protocol Parsers (unchanged from previous version)
class HTTPParser:
    def parse(self, pkt):
        if not hasattr(pkt, 'http'):
            return None
            
        return {
            'method': getattr(pkt.http, 'request_method', ''),
            'uri': getattr(pkt.http, 'request_uri', ''),
            'host': getattr(pkt.http, 'host', ''),
            'user_agent': getattr(pkt.http, 'user_agent', ''),
            'headers': self._parse_headers(pkt),
            'body': self._parse_body(pkt)
        }
        
    def _parse_headers(self, pkt):
        headers = {}
        if hasattr(pkt.http, 'request_line'):
            headers['request_line'] = pkt.http.request_line
        if hasattr(pkt.http, 'response_line'):
            headers['response_line'] = pkt.http.response_line
        return headers
        
    def _parse_body(self, pkt):
        return getattr(pkt.http, 'file_data', '')

class DNSParser:
    def parse(self, pkt):
        if not hasattr(pkt, 'dns'):
            return None
            
        return {
            'query': getattr(pkt.dns, 'qry_name', ''),
            'type': getattr(pkt.dns, 'qry_type', ''),
            'response': getattr(pkt.dns, 'resp_name', ''),
            'answers': self._parse_answers(pkt)
        }
        
    def _parse_answers(self, pkt):
        answers = []
        if hasattr(pkt.dns, 'answers'):
            answers.extend(pkt.dns.answers)
        return answers

class TLSParser:
    def parse(self, pkt):
        if not hasattr(pkt, 'tls'):
            return None
            
        return {
            'handshake_type': getattr(pkt.tls, 'handshake_type', ''),
            'version': getattr(pkt.tls, 'record_version', ''),
            'sni': getattr(pkt.tls, 'handshake_extensions_server_name', ''),
            'ja3': getattr(pkt.tls, 'handshake_ja3_hash', '')
        }

class SSHParser:
    def parse(self, pkt):
        if not hasattr(pkt, 'ssh'):
            return None
            
        return {
            'version': getattr(pkt.ssh, 'protocol_version', ''),
            'software': getattr(pkt.ssh, 'software_version', ''),
            'client_kex': getattr(pkt.ssh, 'client_key_exchange', '')
        }

class FTPParser:
    def parse(self, pkt):
        if not hasattr(pkt, 'ftp'):
            return None
            
        return {
            'command': getattr(pkt.ftp, 'request_command', ''),
            'arg': getattr(pkt.ftp, 'request_arg', ''),
            'response': getattr(pkt.ftp, 'response_arg', '')
        }

class SMTPParser:
    def parse(self, pkt):
        if not hasattr(pkt, 'smtp'):
            return None
            
        return {
            'command': getattr(pkt.smtp, 'req_command', ''),
            'arg': getattr(pkt.smtp, 'req_arg', ''),
            'response': getattr(pkt.smtp, 'rsp', '')
        }

class FlowTracker:
    """Basic flow tracking for stateful analysis"""
    def __init__(self):
        self.flows = {}
        
    def update(self, pkt):
        """Update flow state based on packet"""
        flow_key = self._get_flow_key(pkt)
        if flow_key not in self.flows:
            self.flows[flow_key] = {
                'start_time': datetime.now(),
                'packet_count': 0,
                'bytes': 0,
                'protocol_states': {}
            }
        self.flows[flow_key]['packet_count'] += 1
        self.flows[flow_key]['bytes'] += int(getattr(pkt, 'length', 0))
        
    def _get_flow_key(self, pkt):
        """Create a flow key from packet"""
        src_ip = getattr(pkt.ip, 'src', '0.0.0.0') if hasattr(pkt, 'ip') else '0.0.0.0'
        dst_ip = getattr(pkt.ip, 'dst', '0.0.0.0') if hasattr(pkt, 'ip') else '0.0.0.0'
        src_port = '0'
        dst_port = '0'
        
        if hasattr(pkt, 'tcp'):
            src_port = pkt.tcp.srcport
            dst_port = pkt.tcp.dstport
        elif hasattr(pkt, 'udp'):
            src_port = pkt.udp.srcport
            dst_port = pkt.udp.dstport
            
        return (src_ip, src_port, dst_ip, dst_port, pkt.highest_layer if hasattr(pkt, 'highest_layer') else 'unknown')

if __name__ == "__main__":
    analyzer = PCAPAnalyzer()
    analyzer.analyze_pcaps()
