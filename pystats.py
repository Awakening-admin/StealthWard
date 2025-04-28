import os
import json
import time
from collections import defaultdict
from datetime import datetime
import pandas as pd
import plotly.express as px
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from src.utils import LOGS_DIR, PCAP_DIR, logger
import threading
from functools import lru_cache

class StatsGenerator:
    def __init__(self):
        self.log_stats_file = '/home/robot/edr_server/log_stats.json'
        self.pcap_stats_file = '/home/robot/edr_server/pcap_stats.json'
        self.cache_file = '/home/robot/edr_server/stats_cache.json'
        self.cache_expiry = 300  # 5 minutes cache expiry
        self.last_generated = 0
        self.lock = threading.Lock()
        self.ensure_stats_files()
        self._protocol_hints = {  # Predefined protocol detection hints
            'http': ['http'],
            'dns': ['dns'],
            'tls': ['tls', 'ssl']
        }

    @lru_cache(maxsize=1)
    def get_cached_stats(self):
        """Get cached stats with automatic refresh"""
        current_time = time.time()
        if current_time - self.last_generated > self.cache_expiry:
            with self.lock:
                if current_time - self.last_generated > self.cache_expiry:
                    self.generate_all_stats()
                    self.last_generated = current_time

        try:
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                'log_stats': [],
                'pcap_stats': [],
                'network_stats': {
                    'packet_count': 0,
                    'average_packet_size': 0,
                    'peak_traffic': 0,
                    'total_traffic': 0,
                    'top_protocols': [],
                    'top_ips': []
                }
            }

    def generate_all_stats(self):
        """Generate all stats and cache them"""
        # Use threading to generate stats in parallel
        log_thread = threading.Thread(target=self.generate_log_stats)
        pcap_thread = threading.Thread(target=self.generate_pcap_stats)

        log_thread.start()
        pcap_thread.start()

        log_thread.join()
        pcap_thread.join()

        network_stats = self.generate_network_stats()

        cache_data = {
            'log_stats': self._load_json_file(self.log_stats_file, []),
            'pcap_stats': self._load_json_file(self.pcap_stats_file, []),
            'network_stats': network_stats,
            'timestamp': time.time()
        }

        with open(self.cache_file, 'w') as f:
            json.dump(cache_data, f)

        return cache_data

    def _load_json_file(self, filepath, default):
        """Helper to safely load JSON files"""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return default

    def ensure_stats_files(self):
        """Ensure stats files exist with empty structure if not present"""
        for filepath in [self.log_stats_file, self.pcap_stats_file]:
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    json.dump([], f)

    def _detect_protocol(self, filename):
        """Optimized protocol detection from filename"""
        filename_lower = filename.lower()
        for protocol, hints in self._protocol_hints.items():
            if any(hint in filename_lower for hint in hints):
                return protocol
        return 'unknown'

    def _parse_log_line(self, line, ip_folder, log_file):
        """Optimized log line parsing"""
        if not line.strip():
            return None

        parts = line.strip().split(maxsplit=3)
        if len(parts) < 4:
            return None

        return {
            'ip': ip_folder,
            'timestamp': ' '.join(parts[:2]),
            'log_type': log_file.replace('.log', ''),
            'log_level': parts[2],
            'message': parts[3]
        }

    def generate_log_stats(self):
        """Generate statistics from log files with improved efficiency"""
        log_stats = []
        max_logs = 1000  # Limit to most recent logs

        try:
            for ip_folder in os.listdir(LOGS_DIR):
                ip_path = os.path.join(LOGS_DIR, ip_folder)
                if not os.path.isdir(ip_path):
                    continue

                for log_file in os.listdir(ip_path):
                    if not log_file.endswith('.log'):
                        continue

                    log_path = os.path.join(ip_path, log_file)
                    try:
                        with open(log_path, 'r') as f:
                            for line in f:
                                if len(log_stats) >= max_logs:
                                    break

                                log_entry = self._parse_log_line(line, ip_folder, log_file)
                                if log_entry:
                                    log_stats.append(log_entry)
                    except Exception as e:
                        logger.error(f"Error processing log file {log_path}: {e}")
                        continue

        except Exception as e:
            logger.error(f"Error during log processing: {e}")

        # Sort by timestamp and keep only the most recent
        recent_logs = sorted(log_stats,
                           key=lambda x: x.get('timestamp', ''),
                           reverse=True)[:max_logs]

        with open(self.log_stats_file, 'w') as f:
            json.dump(recent_logs, f)

        return recent_logs

    def _parse_pcap_filename(self, pcap_file):
        """Optimized PCAP filename parsing"""
        filename_parts = pcap_file.split('_')
        if len(filename_parts) >= 3:
            source_ip = filename_parts[1]
            protocol = filename_parts[2].split('.')[0]
            if protocol == 'unknown':
                protocol = self._detect_protocol(pcap_file)
            return source_ip, protocol
        return "unknown", "unknown"

    def generate_pcap_stats(self):
        """Generate statistics from PCAP files with enhanced efficiency"""
        pcap_stats = []

        try:
            for pcap_file in os.listdir(PCAP_DIR):
                if not pcap_file.endswith('.pcap'):
                    continue

                pcap_path = os.path.join(PCAP_DIR, pcap_file)
                try:
                    source_ip, protocol = self._parse_pcap_filename(pcap_file)
                    file_size = os.path.getsize(pcap_path)
                    creation_time = datetime.fromtimestamp(os.path.getctime(pcap_path))
                    packet_count = max(1, file_size // 1024)

                    pcap_stats.append({
                        'source_ip': source_ip,
                        'destination_ip': 'multiple',
                        'protocol': protocol,
                        'packet_count': packet_count,
                        'total_size': file_size,
                        'timestamp': creation_time.isoformat(),
                        'filename': pcap_file
                    })

                except Exception as e:
                    logger.error(f"Error processing PCAP file {pcap_file}: {e}")

        except Exception as e:
            logger.error(f"Error during PCAP processing: {e}")

        with open(self.pcap_stats_file, 'w') as f:
            json.dump(pcap_stats, f)

        return pcap_stats

    def generate_network_stats(self):
        """Generate network stats with optimized processing"""
        pcap_stats = self._load_json_file(self.pcap_stats_file, [])

        protocol_counter = defaultdict(int)
        ip_counter = defaultdict(int)
        total_packets = 0
        total_size = 0

        for stat in pcap_stats:
            try:
                protocol = stat.get('protocol', 'unknown').lower()
                if protocol == 'unknown':
                    protocol = self._detect_protocol(stat.get('filename', ''))

                source_ip = stat.get('source_ip', 'unknown')
                if source_ip == 'unknown':
                    filename = stat.get('filename', '')
                    ip_parts = [p for p in filename.split('_') if p.replace('.', '').isdigit()]
                    if ip_parts:
                        source_ip = ip_parts[0]

                packet_count = int(stat.get('packet_count', 0))
                size = int(stat.get('total_size', 0))

                protocol_counter[protocol] += packet_count
                ip_counter[source_ip] += packet_count
                total_packets += packet_count
                total_size += size

            except Exception as e:
                logger.error(f"Error processing pcap stat: {e}")
                continue

        # Filter out invalid data
        protocol_counter = {k:v for k,v in protocol_counter.items() if v > 0}
        ip_counter = {k:v for k,v in ip_counter.items() if v > 0 and k != 'unknown'}

        top_protocols = sorted(protocol_counter.items(),
                             key=lambda x: x[1],
                             reverse=True)[:5]
        top_ips = sorted(ip_counter.items(),
                        key=lambda x: x[1],
                        reverse=True)[:5]

        return {
            'packet_count': total_packets,
            'average_packet_size': round(total_size / total_packets, 2) if total_packets else 0,
            'peak_traffic': max(ip_counter.values(), default=0),
            'total_traffic': total_size,
            'top_protocols': top_protocols,
            'top_ips': top_ips
        }

class StatsMonitor(FileSystemEventHandler):
    def __init__(self, stats_generator):
        self.stats_generator = stats_generator
        self.last_update = time.time()
        self.update_interval = 5  # seconds

    def on_modified(self, event):
        if not event.is_directory:
            current_time = time.time()
            if current_time - self.last_update > self.update_interval:
                self.last_update = current_time
                logger.info("Detected file changes, refreshing stats cache")
                # Use threading to avoid blocking
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

    observer.schedule(event_handler, LOGS_DIR, recursive=True)
    observer.schedule(event_handler, PCAP_DIR, recursive=False)

    observer.start()
    logger.info("Started stats monitoring service")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def manual_generate_stats():
    """Manually generate stats without monitoring"""
    generator = StatsGenerator()
    generator.generate_log_stats()
    generator.generate_pcap_stats()
    logger.info("Manually generated stats files")

if __name__ == '__main__':
    generator = StatsGenerator()
    generator.generate_log_stats()
    generator.generate_pcap_stats()
    start_stats_monitoring()

__all__ = ['StatsGenerator', 'start_stats_monitoring', 'manual_generate_stats']
