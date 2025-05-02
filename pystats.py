import os
import json
import time
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
from functools import lru_cache
import hashlib
from scapy.all import rdpcap, TCP, UDP, ICMP, DNS
from scapy.layers.http import HTTPRequest, HTTPResponse


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class StatsGenerator:
    def __init__(self):
        # Configuration paths
        self.logs_dir = "/home/robot/edr_server/Logs"
        self.pcap_dir = "/home/robot/edr_server/pcap_files"
        self.alerts_dir = "/home/robot/edr_server/alerts"
        self.threats_file = "/home/robot/edr_server/network_threats.json"
        self.admin_alerts_file = "/home/robot/edr_server/ids_admin_log_alerts.json"
        self.pcap_alerts_file = "/home/robot/edr_server/ids_pcap_alerts.json"

        # Cache settings
        self.stats_file = '/home/robot/edr_server/stats_cache.json'
        self.cache_expiry = 300
        self.last_generated = 0
        self.lock = threading.Lock()

        # File hashes for change detection
        self.file_hashes = {}
        self.last_check_time = 0

        # Protocol detection hints
        self._protocol_hints = {
            'http': ['http', '80', 'get ', 'post '],
            'https': ['https', 'tls', 'ssl', '443'],
            'dns': ['dns', '53', 'query'],
            'ssh': ['ssh', '22'],
            'ftp': ['ftp', '21'],
            'smb': ['smb', '445'],
            'icmp': ['icmp', 'ping'],
            'dhcp': ['dhcp', '67', '68'],
            'ntp': ['ntp', '123']
        }

        # Severity colors
        self.severity_colors = {
            'critical': '#FF0000',
            'high': '#FF4500',
            'medium': '#FFA500',
            'low': '#FFFF00',
            'info': '#ADD8E6'
        }

    def _file_changed(self, filepath):
        """Check if a file has changed since last check using hash"""
        if not os.path.exists(filepath):
            return False

        current_hash = self._file_hash(filepath)
        last_hash = self.file_hashes.get(filepath)

        if last_hash is None or current_hash != last_hash:
            self.file_hashes[filepath] = current_hash
            return True
        return False

    def _file_hash(self, filepath):
        """Generate a hash of a file's contents"""
        if not os.path.exists(filepath):
            return ""

        hasher = hashlib.md5()
        with open(filepath, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()

    def _directory_changed(self, dirpath):
        """Check if any files in directory have changed"""
        if not os.path.exists(dirpath):
            return False

        for root, _, files in os.walk(dirpath):
            for file in files:
                filepath = os.path.join(root, file)
                if self._file_changed(filepath):
                    return True
        return False

    def needs_regeneration(self):
        """Check if stats need to be regenerated"""
        if not os.path.exists(self.stats_file):
            return True

        current_time = time.time()
        if current_time - self.last_generated > self.cache_expiry:
            return True

        paths_to_check = [
            self.logs_dir,
            self.pcap_dir,
            self.alerts_dir,
            self.threats_file,
            self.admin_alerts_file,
            self.pcap_alerts_file
        ]

        for path in paths_to_check:
            if os.path.isdir(path):
                if self._directory_changed(path):
                    return True
            elif os.path.isfile(path):
                if self._file_changed(path):
                    return True

        return False

    @lru_cache(maxsize=1)
    def get_cached_stats(self):
        """Get cached stats with automatic refresh when needed"""
        if self.needs_regeneration():
            with self.lock:
                if self.needs_regeneration():
                    self.generate_all_stats()
                    self.last_generated = time.time()

        try:
            with open(self.stats_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return self._default_stats()

    def _default_stats(self):
        """Return default empty stats structure"""
        return {
            'log_stats': [],
            'network_stats': {
                'packet_count': 0,
                'average_packet_size': 0,
                'peak_traffic': 0,
                'total_traffic': 0,
                'top_protocols': [],
                'top_ips': [],
                'traffic_trend': []
            },
            'threat_stats': {
                'total_threats': 0,
                'threats_by_severity': [],
                'threats_by_type': [],
                'recent_threats': [],
                'top_source_ips': [],
                'attack_patterns': [],
                'target_ports': [],
                'threat_sources': []
            },
            'endpoint_stats': {
                'total_endpoints': 0,
                'active_endpoints': [],
                'endpoint_activity': [],
                'compromised_endpoints': []
            },
            'timestamp': time.time(),
            'visualizations': {
                'protocol_distribution': '',
                'traffic_volume': '',
                'threat_severity': '',
                'top_talkers': '',
                'attack_types': '',
                'target_ports_chart': '',
                'threat_sources': '',
                'compromised_endpoints': ''
            }
        }

    def generate_all_stats(self):
        """Generate all stats and cache them"""
        stats = self._default_stats()

        try:
            threads = [
                threading.Thread(target=self._generate_log_stats, args=(stats,)),
                threading.Thread(target=self._generate_network_stats, args=(stats,)),
                threading.Thread(target=self._generate_threat_stats, args=(stats,)),
                threading.Thread(target=self._generate_endpoint_stats, args=(stats,)),
                threading.Thread(target=self._generate_alerts_stats, args=(stats,))
            ]

            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self._generate_visualizations(stats)

            stats['timestamp'] = time.time()
            temp_file = self.stats_file + '.tmp'

            try:
                with open(temp_file, 'w') as f:
                    json.dump(stats, f, cls=DateTimeEncoder, ensure_ascii=False, indent=2)
                os.replace(temp_file, self.stats_file)
            except Exception as e:
                print(f"Failed to write stats cache: {str(e)}")
                if os.path.exists(temp_file):
                    os.remove(temp_file)

        except Exception as e:
            print(f"Error generating stats: {str(e)}")

        return stats

    def _generate_log_stats(self, stats):
        """Generate statistics from log files with proper severity extraction"""
        try:
            log_entries = []
            ip_activity = defaultdict(int)

            if not os.path.exists(self.logs_dir):
                return

            for ip_folder in os.listdir(self.logs_dir):
                ip_path = os.path.join(self.logs_dir, ip_folder)
                if not os.path.isdir(ip_path):
                    continue

                for log_file in os.listdir(ip_path):
                    if not log_file.endswith('.log'):
                        continue

                    log_path = os.path.join(ip_path, log_file)
                    try:
                        with open(log_path, 'r') as f:
                            for line in f:
                                if line.strip():
                                    ip_activity[ip_folder] += 1
                                    
                                    # Extract severity from log line
                                    severity = 'info'
                                    message = line.strip()
                                    
                                    # Simple severity detection (customize for your log format)
                                    line_lower = line.lower()
                                    if 'critical' in line_lower:
                                        severity = 'critical'
                                    elif 'error' in line_lower:
                                        severity = 'high'
                                    elif 'warning' in line_lower:
                                        severity = 'medium'
                                    elif 'notice' in line_lower:
                                        severity = 'low'
                                    
                                    log_entries.append({
                                        'ip': ip_folder,
                                        'log_type': log_file,
                                        'timestamp': datetime.now().isoformat(),
                                        'severity': severity,
                                        'message': message
                                    })
                    except Exception as e:
                        print(f"Error processing log file {log_path}: {e}")

            stats['log_stats'] = log_entries[-1000:]  # Keep only recent logs
            stats['endpoint_stats']['active_endpoints'] = [
                {'ip': ip, 'activity': count}
                for ip, count in ip_activity.items()
            ]

        except Exception as e:
            print(f"Error generating log stats: {e}")

    def _generate_network_stats(self, stats):
        """Generate network statistics from PCAP files with proper protocol analysis"""
        try:
            protocol_counter = Counter()
            ip_counter = Counter()
            traffic_data = []
            total_packets = 0
            total_size = 0

            if not os.path.exists(self.pcap_dir):
                return

            for pcap_file in os.listdir(self.pcap_dir):
                if not pcap_file.endswith('.pcap'):
                    continue

                pcap_path = os.path.join(self.pcap_dir, pcap_file)
                try:
                    # Extract source IP from filename (format: pcap_<IP>_<timestamp>.pcap)
                    parts = pcap_file.split('_')
                    source_ip = parts[1] if len(parts) > 1 else 'unknown'
                    
                    # Get file size and creation time
                    size = os.path.getsize(pcap_path)
                    timestamp = datetime.fromtimestamp(os.path.getctime(pcap_path))
                    
                    # Analyze PCAP file for protocols
                    protocols = self._analyze_pcap_protocols(pcap_path)
                    if not protocols:
                        protocols = ['unknown']
                    
                    # Estimate packet count (this is just an approximation)
                    packet_count = max(1, size // 1500)  # Assuming average packet size of 1500 bytes
                    
                    for protocol in protocols:
                        protocol_counter[protocol] += packet_count
                    ip_counter[source_ip] += packet_count
                    total_packets += packet_count
                    total_size += size

                    hour = timestamp.replace(minute=0, second=0, microsecond=0)
                    traffic_data.append({
                        'hour': hour,
                        'packets': packet_count,
                        'size': size,
                        'protocol': protocols[0],  # Use first protocol for trend grouping
                        'source_ip': source_ip
                    })

                except Exception as e:
                    print(f"Error processing PCAP {pcap_file}: {e}")

            # Generate traffic trend data
            if traffic_data:
                traffic_df = pd.DataFrame(traffic_data)
                traffic_df['hour'] = traffic_df['hour'].dt.strftime('%Y-%m-%d %H:%M:%S')
                traffic_trend = traffic_df.groupby(['hour', 'protocol']).sum().reset_index()
                stats['network_stats']['traffic_trend'] = traffic_trend.to_dict('records')

            # Update network stats
            stats['network_stats'].update({
                'packet_count': total_packets,
                'average_packet_size': round(total_size / total_packets, 2) if total_packets else 0,
                'peak_traffic': max(ip_counter.values(), default=0),
                'total_traffic': total_size,
                'top_protocols': protocol_counter.most_common(10),
                'top_ips': ip_counter.most_common(5)
            })

        except Exception as e:
            print(f"Error generating network stats: {e}")

    def _analyze_pcap_protocols(self, pcap_path):
        """Analyze PCAP file to detect protocols"""
        protocols = set()
        try:
            # Read first 100 packets to determine protocols (for performance)
            packets = rdpcap(pcap_path, count=100)
            
            for pkt in packets:
                if pkt.haslayer(TCP):
                    if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                        protocols.add('http')
                    elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                        protocols.add('https')
                    elif pkt[TCP].dport == 22 or pkt[TCP].sport == 22:
                        protocols.add('ssh')
                    elif pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
                        protocols.add('ftp')
                    elif pkt[TCP].dport == 445 or pkt[TCP].sport == 445:
                        protocols.add('smb')
                elif pkt.haslayer(UDP):
                    if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                        protocols.add('dns')
                    elif pkt[UDP].dport == 67 or pkt[UDP].sport == 68:
                        protocols.add('dhcp')
                    elif pkt[UDP].dport == 123 or pkt[UDP].sport == 123:
                        protocols.add('ntp')
                elif pkt.haslayer(ICMP):
                    protocols.add('icmp')
                elif pkt.haslayer(DNS):
                    protocols.add('dns')
                elif pkt.haslayer(HTTP):
                    protocols.add('http')
            
            # Fallback to filename analysis if no protocols detected
            if not protocols:
                filename = os.path.basename(pcap_path).lower()
                for protocol, hints in self._protocol_hints.items():
                    if any(hint in filename for hint in hints):
                        protocols.add(protocol)
            
            return list(protocols) if protocols else ['unknown']
        except Exception as e:
            print(f"Error analyzing PCAP {pcap_path}: {e}")
            return ['unknown']

    def _generate_threat_stats(self, stats):
        """Generate threat statistics from IDS alerts"""
        try:
            threat_sources = {
                'Admin Logs': self._load_threats_from_file(self.admin_alerts_file),
                'Endpoint Logs': self._find_log_threats(),
                'PCAP Files': self._load_threats_from_file(self.pcap_alerts_file),
                'Network': self._load_threats_from_file(self.threats_file)
            }

            all_alerts = []
            for source, alerts in threat_sources.items():
                if alerts:
                    for alert in alerts:
                        alert['source'] = source
                    all_alerts.extend(alerts)

            if not all_alerts:
                return

            severity_counter = Counter()
            type_counter = Counter()
            source_ip_counter = Counter()
            recent_threats = []

            for alert in all_alerts:
                try:
                    severity = alert.get('severity', 'medium').lower()
                    alert_type = alert.get('type', alert.get('rule_name', 'unknown'))
                    src_ip = alert.get('source_ip', alert.get('endpoint_ip', 'unknown'))

                    severity_counter[severity] += 1
                    type_counter[alert_type] += 1
                    if src_ip != 'unknown':
                        source_ip_counter[src_ip] += 1

                    alert_time_str = alert.get('timestamp', '')
                    if alert_time_str:
                        try:
                            alert_time = datetime.fromisoformat(alert_time_str.split('+')[0])
                            if datetime.now() - alert_time < timedelta(days=1):
                                recent_threats.append(alert)
                        except ValueError:
                            continue

                except Exception as e:
                    print(f"Error processing alert: {e}")
                    continue

            # Count threats by source
            source_counter = Counter()
            for alert in all_alerts:
                source_counter[alert.get('source', 'unknown')] += 1

            stats['threat_stats'].update({
                'total_threats': len(all_alerts),
                'threats_by_severity': severity_counter.most_common(),
                'threats_by_type': type_counter.most_common(10),
                'recent_threats': recent_threats[-10:],
                'top_source_ips': source_ip_counter.most_common(5),
                'threat_sources': source_counter.most_common()
            })

        except Exception as e:
            print(f"Error generating threat stats: {e}")

    def _load_threats_from_file(self, filepath):
        """Load threats from a JSON file"""
        if not os.path.exists(filepath):
            return []

        try:
            with open(filepath, 'r') as f:
                alerts = json.load(f)
                return alerts if isinstance(alerts, list) else [alerts]
        except Exception as e:
            print(f"Error loading threat file {filepath}: {e}")
            return []

    def _find_log_threats(self):
        """Find threats in log files"""
        threats = []
        if not os.path.exists(self.logs_dir):
            return threats

        for ip_folder in os.listdir(self.logs_dir):
            ip_path = os.path.join(self.logs_dir, ip_folder)
            if not os.path.isdir(ip_path):
                continue

            for log_file in os.listdir(ip_path):
                if not log_file.endswith('.log'):
                    continue

                log_path = os.path.join(ip_path, log_file)
                try:
                    with open(log_path, 'r') as f:
                        for line in f:
                            line_lower = line.lower()
                            if "alert" in line_lower or "threat" in line_lower or "attack" in line_lower:
                                severity = 'medium'
                                if 'critical' in line_lower:
                                    severity = 'critical'
                                elif 'high' in line_lower:
                                    severity = 'high'
                                
                                threats.append({
                                    'source_ip': ip_folder,
                                    'type': 'log_alert',
                                    'severity': severity,
                                    'timestamp': datetime.now().isoformat(),
                                    'message': line.strip(),
                                    'source': 'Endpoint Logs'
                                })
                except Exception as e:
                    print(f"Error processing log file {log_path}: {e}")

        return threats

    def _generate_alerts_stats(self, stats):
        """Generate statistics from endpoint alerts.json files"""
        try:
            if not os.path.exists(self.alerts_dir):
                return

            attack_counter = Counter()
            port_counter = Counter()
            compromised_ips = set()
            source_ip_counter = Counter()
            severity_counter = Counter()
            all_alerts = []

            for alert_file in os.listdir(self.alerts_dir):
                if not alert_file.startswith('alerts_') or not alert_file.endswith('.json'):
                    continue

                alert_path = os.path.join(self.alerts_dir, alert_file)
                try:
                    with open(alert_path, 'r') as f:
                        alerts = json.load(f)
                        if not isinstance(alerts, list):
                            alerts = [alerts]

                        for alert in alerts:
                            try:
                                attack_type = alert.get('attack_type', 'unknown')
                                dest_port = alert.get('destination_port', 0)
                                dest_ip = alert.get('destination_ip', 'unknown')
                                src_ip = alert.get('source_ip', 'unknown')
                                severity = alert.get('severity', 'medium').lower()
                                timestamp = alert.get('timestamp', '')

                                attack_counter[attack_type] += 1
                                port_counter[dest_port] += 1
                                source_ip_counter[src_ip] += 1
                                severity_counter[severity] += 1

                                if dest_ip != 'unknown':
                                    compromised_ips.add(dest_ip)

                                if timestamp:
                                    try:
                                        alert_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                                        if datetime.now() - alert_time < timedelta(days=1):
                                            all_alerts.append(alert)
                                    except ValueError:
                                        continue

                            except Exception as e:
                                print(f"Error processing alert in {alert_file}: {e}")
                                continue

                except Exception as e:
                    print(f"Error loading alert file {alert_file}: {e}")
                    continue

            # Merge with existing stats
            existing_severity = Counter(dict(stats['threat_stats'].get('threats_by_severity', [])))
            existing_source_ips = Counter(dict(stats['threat_stats'].get('top_source_ips', [])))
            existing_recent_threats = stats['threat_stats'].get('recent_threats', [])

            stats['threat_stats'].update({
                'attack_patterns': attack_counter.most_common(),
                'target_ports': port_counter.most_common(),
                'total_threats': stats['threat_stats'].get('total_threats', 0) + sum(attack_counter.values()),
                'threats_by_severity': (severity_counter + existing_severity).most_common(),
                'top_source_ips': (source_ip_counter + existing_source_ips).most_common(5),
                'recent_threats': (existing_recent_threats + all_alerts)[-10:]
            })

            stats['endpoint_stats']['compromised_endpoints'] = list(compromised_ips)

        except Exception as e:
            print(f"Error generating alerts stats: {e}")

    def _generate_endpoint_stats(self, stats):
        """Generate endpoint activity statistics based on Logs directory"""
        try:
            endpoints = set()

            # Active endpoints are directories in Logs folder
            if os.path.exists(self.logs_dir):
                for ip_folder in os.listdir(self.logs_dir):
                    ip_path = os.path.join(self.logs_dir, ip_folder)
                    if os.path.isdir(ip_path):
                        endpoints.add(ip_folder)

            stats['endpoint_stats'].update({
                'total_endpoints': len(endpoints),
                'active_endpoints': list(endpoints)
            })

        except Exception as e:
            print(f"Error generating endpoint stats: {e}")

    def _generate_visualizations(self, stats):
        """Generate Plotly visualizations for the dashboard"""
        try:
            # Protocol Distribution Pie Chart
            if stats['network_stats']['top_protocols']:
                protocols, counts = zip(*stats['network_stats']['top_protocols'])
                fig = px.pie(
                    names=protocols,
                    values=counts,
                    title='Protocol Distribution (PCAP Analysis)',
                    color_discrete_sequence=px.colors.qualitative.Pastel,
                    hover_data={'protocol': protocols, 'count': counts}
                )
                stats['visualizations']['protocol_distribution'] = fig.to_html(full_html=False)

            # Network Traffic Trend
            if stats['network_stats']['traffic_trend']:
                df = pd.DataFrame(stats['network_stats']['traffic_trend'])
                fig = px.area(
                    df, x='hour', y='packets', color='protocol',
                    title='Network Traffic Volume (PCAP Data)',
                    labels={'hour': 'Time', 'packets': 'Packets'},
                    color_discrete_sequence=px.colors.qualitative.Pastel
                )
                stats['visualizations']['traffic_volume'] = fig.to_html(full_html=False)

            # Threats by Severity
            if stats['threat_stats']['threats_by_severity']:
                severities, counts = zip(*stats['threat_stats']['threats_by_severity'])
                fig = px.bar(
                    x=severities, y=counts,
                    title='Threats by Severity',
                    color=severities,
                    color_discrete_map=self.severity_colors,
                    labels={'x': 'Severity', 'y': 'Count'}
                )
                stats['visualizations']['threat_severity'] = fig.to_html(full_html=False)

            # Top Talkers
            if stats['network_stats']['top_ips']:
                ips, counts = zip(*stats['network_stats']['top_ips'])
                fig = px.bar(
                    x=ips, y=counts,
                    title='Top Talkers by Packet Count',
                    labels={'x': 'IP Address', 'y': 'Packets'},
                    color=counts,
                    color_continuous_scale='Viridis'
                )
                stats['visualizations']['top_talkers'] = fig.to_html(full_html=False)

            # Attack Types
            if stats['threat_stats'].get('attack_patterns'):
                attacks, counts = zip(*stats['threat_stats']['attack_patterns'])
                fig = px.bar(
                    x=attacks, y=counts,
                    title='Attack Types Distribution',
                    labels={'x': 'Attack Type', 'y': 'Count'},
                    color=counts,
                    color_continuous_scale='Viridis'
                )
                stats['visualizations']['attack_types'] = fig.to_html(full_html=False)

            # Target Ports
            if stats['threat_stats'].get('target_ports'):
                ports, counts = zip(*stats['threat_stats']['target_ports'])
                fig = px.bar(
                    x=[str(p) for p in ports], y=counts,
                    title='Target Ports Distribution',
                    labels={'x': 'Port', 'y': 'Attack Count'},
                    color=counts,
                    color_continuous_scale='Viridis'
                )
                stats['visualizations']['target_ports_chart'] = fig.to_html(full_html=False)

            # Threats by Source
            if stats['threat_stats'].get('threat_sources'):
                sources, counts = zip(*stats['threat_stats']['threat_sources'])
                fig = px.pie(
                    names=sources,
                    values=counts,
                    title='Threats by Source',
                    color_discrete_sequence=px.colors.qualitative.Pastel
                )
                stats['visualizations']['threat_sources'] = fig.to_html(full_html=False)

            # Compromised Endpoints with Hover
            if stats['endpoint_stats'].get('compromised_endpoints'):
                ips = stats['endpoint_stats']['compromised_endpoints']
                hover_text = "<br>".join(ips)
                fig = go.Figure(go.Indicator(
                    mode="number",
                    value=len(ips),
                    title="Compromised Devices"
                ))
                fig.update_layout(
                    hoverlabel=dict(
                        bgcolor="white",
                        font_size=12,
                        font_family="Rockwell"
                    )
                )
                fig.add_trace(go.Scatter(
                    x=[None], y=[None],
                    hovertext=hover_text,
                    hoverinfo="text",
                    mode="markers",
                    marker=dict(opacity=0)
                ))
                stats['visualizations']['compromised_endpoints'] = fig.to_html(full_html=False)

        except Exception as e:
            print(f"Error generating visualizations: {e}")

class StatsMonitor(FileSystemEventHandler):
    def __init__(self, stats_generator):
        self.stats_generator = stats_generator
        self.last_update = time.time()
        self.update_interval = 5

    def on_modified(self, event):
        if not event.is_directory:
            current_time = time.time()
            if current_time - self.last_update > self.update_interval:
                self.last_update = current_time
                print("Detected file changes, refreshing stats cache")
                threading.Thread(target=self._refresh_stats).start()

    def _refresh_stats(self):
        """Thread-safe stats refresh"""
        self.stats_generator.generate_all_stats()
        self.stats_generator.get_cached_stats.cache_clear()

def start_stats_monitoring():
    """Start monitoring directories for changes"""
    stats_generator = StatsGenerator()
    stats_generator.generate_all_stats()

    event_handler = StatsMonitor(stats_generator)
    observer = Observer()
    observer.schedule(event_handler, stats_generator.logs_dir, recursive=True)
    observer.schedule(event_handler, stats_generator.pcap_dir, recursive=True)
    observer.schedule(event_handler, stats_generator.alerts_dir, recursive=True)
    observer.start()

    print("Started stats monitoring service")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == '__main__':
    start_stats_monitoring()
