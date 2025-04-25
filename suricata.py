import os
import json
import time
import concurrent.futures
import glob
import yaml
import pandas as pd
import subprocess
import re
import ipaddress
from collections import Counter, defaultdict
import plotly.express as px
from datetime import datetime, timedelta
import logging
from src.clamav import process_logs_threats, load_rules
from src.utils import SURICATA_LOGS_DIR, PCAP_DIR, PROCESSED_PCAPS_JSON, SURICATA_ALERTS_JSON, logger
from concurrent.futures import ThreadPoolExecutor
import fcntl
TMP_DIR = "/dev/shm/suricata_temp"

# Global variables for threat intelligence
INTERNAL_IPS = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
THREAT_INTEL_FEEDS = {
    'known_malicious_ips': [],
    'tor_exit_nodes': [],
    'crypto_mining_pools': []
}

# Add these constants at the top
HIGH_SEVERITY_CATEGORIES = {
    'exploit', 'malware', 'command and control', 'ddos',
    'attempted-admin', 'attempted-user', 'shellcode'
}

LOW_SEVERITY_CATEGORIES = {
    'not-suspicious', 'unknown', 'misc-activity',
    'potential-exploit', 'network-scan'
}




def save_alerts(alerts):
    """Save alerts to a centralized JSON file with thread-safe locking"""
    try:
        # Create a temporary file first for atomic writes
        temp_file = SURICATA_ALERTS_JSON + '.tmp'
        
        with open(temp_file, 'w') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                json.dump(alerts, f, indent=4)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        
        # Atomic rename
        os.replace(temp_file, SURICATA_ALERTS_JSON)
        
    except Exception as e:
        logger.error(f"Error saving alerts: {str(e)}")

def load_alerts():
    """Load existing alerts from JSON file"""
    if not os.path.exists(SURICATA_ALERTS_JSON):
        return []
    
    try:
        with open(SURICATA_ALERTS_JSON, 'r') as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                return json.load(f)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        logger.error(f"Error loading alerts: {str(e)}")
        return []

def add_alerts(new_alerts):
    """Add new alerts to the existing alerts file"""
    try:
        existing_alerts = load_alerts()
        updated_alerts = existing_alerts + new_alerts
        
        # Deduplicate alerts based on timestamp, signature_id, src_ip, dest_ip
        unique_alerts = []
        seen = set()
        
        for alert in updated_alerts:
            alert_key = (
                alert.get('timestamp'),
                alert.get('signature_id'),
                alert.get('src_ip'),
                alert.get('dest_ip')
            )
            if alert_key not in seen:
                seen.add(alert_key)
                unique_alerts.append(alert)
        
        save_alerts(unique_alerts)
        return True
        
    except Exception as e:
        logger.error(f"Error adding alerts: {str(e)}")
        return False

        
def process_pcap(file_path):
    """Process PCAP file and generate statistics"""
    import pyshark
    capture = pyshark.FileCapture(file_path, use_json=True)
    packets_data = []
    ip_stats = Counter()
    protocols = Counter()

    for packet in capture:
        try:
            packet_info = {
                "time": packet.sniff_time if hasattr(packet, 'sniff_time') else None,
                "source": packet.ip.src if hasattr(packet, 'ip') else None,
                "destination": packet.ip.dst if hasattr(packet, 'ip') else None,
                "protocol": packet.transport_layer if hasattr(packet, 'transport_layer') else None,
                "length": int(packet.length) if hasattr(packet, 'length') else 0,
            }
            packets_data.append(packet_info)
            if packet_info['source'] and packet_info['destination']:
                ip_stats[(packet_info['source'], packet_info['destination'])] += 1
            if packet_info['protocol']:
                protocols[packet_info['protocol']] += 1
        except AttributeError:
            continue

    df = pd.DataFrame(packets_data)
    packets_table = df.to_html(classes="table table-bordered table-striped")

    stats = {
        'protocols': protocols,
        'ip_stats': ip_stats,
        'packets_table': packets_table
    }
    return df, stats

def generate_plot(df):
    """Generate packet length over time plot"""
    fig = px.line(df, x='time', y='length', title='Packet Length Over Time')
    return fig.to_html(full_html=False)

def generate_protocol_pie_chart(protocols):
    """Generate protocol distribution pie chart"""
    labels = list(protocols.keys())
    values = list(protocols.values())
    fig = px.pie(names=labels, values=values, title='Protocol Distribution')
    return fig.to_html(full_html=False)

def generate_ip_stats(ip_stats):
    """Generate IP statistics bar chart"""
    data = {
        "Source IP": [ip[0] for ip in ip_stats.keys()],
        "Destination IP": [ip[1] for ip in ip_stats.keys()],
        "Packets": list(ip_stats.values())
    }
    df = pd.DataFrame(data)
    fig = px.bar(df, x='Source IP', y='Packets', color='Destination IP', title='IP Statistics')
    return fig.to_html(full_html=False)

def run_suricata_analysis(pcap_file):
    """Optimized Suricata analysis with proper PCAP runmode configuration"""
    if not is_tool_installed("suricata"):
        logger.error("Suricata is not installed on the system")
        return None

    pcap_path = os.path.abspath(os.path.join(PCAP_DIR, pcap_file))
    
    # Define output directory
    pcap_base = os.path.splitext(os.path.basename(pcap_file))[0]
    output_dir = os.path.join(SURICATA_LOGS_DIR, pcap_base)
    os.makedirs(output_dir, exist_ok=True)

    # Correct command with proper runmode configuration
    cmd = [
        "suricata",
        "-r", pcap_path,  # Input PCAP file
        "-l", output_dir,  # Log directory
        "-S", "/var/lib/suricata/rules/suricata.rules",
        "--runmode", "autofp"  # Using autofp runmode which is standard for PCAP processing
    ]

    try:
        start_time = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        duration = time.time() - start_time
        logger.info(f"Suricata processed {pcap_file} in {duration:.2f} seconds")

        if result.returncode != 0:
            if result.stderr:
                error_msg = result.stderr[:500]
                logger.error(f"Suricata error: {error_msg}")
                if "runmodes" in error_msg:
                    logger.warning("Try updating Suricata or check configuration")
            return None

        # Verify output was created
        eve_json = os.path.join(output_dir, "eve.json")
        if os.path.exists(eve_json):
            return output_dir
        logger.error(f"No eve.json output created in {output_dir}")
        return None

    except Exception as e:
        logger.error(f"Suricata exception processing {pcap_file}: {str(e)}")
        return None
        
def log_processing_speed():
    """Log processing statistics"""
    processed_count = 0
    total_time = 0
    while True:
        try:
            current_count = len(load_processed_pcaps())
            if current_count > processed_count:
                if total_time > 0:  # Avoid division by zero
                    speed = (current_count - processed_count) / (time.time() - total_time)
                    logger.info(f"Processing speed: {speed:.2f} PCAPs/second")
                else:
                    logger.info(f"Initial processing count: {current_count}")

                processed_count = current_count
                total_time = time.time()
            time.sleep(10)
        except Exception as e:
            logger.error(f"Error in log_processing_speed: {str(e)}", exc_info=True)
            time.sleep(30)


def verify_suricata_rules():
    """Verify that Suricata rules are loading correctly"""
    try:
        # Count rules in the suricata.rules file
        with open('/var/lib/suricata/rules/suricata.rules', 'r') as f:
            rule_count = sum(1 for line in f if line.startswith('alert'))

        logger.info(f"Found {rule_count} Suricata rules")
        return rule_count > 0

    except Exception as e:
        logger.error(f"Rule verification failed: {str(e)}")
        return False


def parse_suricata_logs(log_dir):
    """Parse Suricata's eve.json alerts"""
    eve_file = os.path.join(log_dir, "eve.json")
    if not os.path.exists(eve_file):
        return []

    alerts = []
    with open(eve_file, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
                if entry['event_type'] == 'alert':
                    alerts.append(entry)
            except json.JSONDecodeError:
                continue
    return alerts

def process_suricata_alerts(alerts):
    """Classify and filter Suricata alerts by severity"""
    serious_threats = []
    minor_alerts = []
    all_processed_alerts = []

    for alert in alerts:
        category = alert['alert']['category'].lower()
        severity = map_suricata_severity(alert['alert']['severity'])

        processed_alert = {
            'timestamp': alert['timestamp'],
            'signature_id': alert['alert']['signature_id'],
            'signature': alert['alert']['signature'],
            'category': category,
            'severity': severity,
            'src_ip': alert.get('src_ip', 'unknown'),
            'dest_ip': alert.get('dest_ip', 'unknown'),
            'proto': alert.get('proto', 'unknown'),
            'is_serious': category in HIGH_SEVERITY_CATEGORIES or severity in ['critical', 'high']
        }

        all_processed_alerts.append(processed_alert)
        
        if processed_alert['is_serious']:
            serious_threats.append(processed_alert)
        else:
            minor_alerts.append(processed_alert)

    # Save all alerts to the central file
    add_alerts(all_processed_alerts)

    return {
        'serious_threats': serious_threats,
        'minor_alerts': minor_alerts
    }


def map_suricata_severity(level):
    """Map Suricata severity levels to consistent values"""
    return {
        1: 'critical',
        2: 'high',
        3: 'medium',
        4: 'low'
    }.get(level, 'medium')




def continuous_suricata_analysis():
    """Monitor PCAP directory and process new files"""
    processed_pcaps = load_processed_pcaps()
    logger.info(f"Initial processed PCAPs: {len(processed_pcaps)}")

    while True:
        try:
            current_pcaps = set(f for f in os.listdir(PCAP_DIR) if f.endswith(".pcap"))
            new_pcaps = current_pcaps - processed_pcaps

            if new_pcaps:
                logger.info(f"\n=== Found {len(new_pcaps)} new PCAPs at {datetime.now()} ===")
                
                # Process files sorted by size (smallest first)
                for pcap_file in sorted(new_pcaps, key=lambda x: os.path.getsize(os.path.join(PCAP_DIR, x))):
                    try:
                        output_dir = process_single_pcap(pcap_file)
                        if output_dir:  # Only mark as processed if successful
                            processed_pcaps.add(pcap_file)
                            save_processed_pcaps(processed_pcaps)
                    except Exception as e:
                        logger.error(f"Error processing {pcap_file}: {str(e)}")
                        continue

                # Add delay after processing batch
                time.sleep(10)
            else:
                # Longer delay when no new files
                time.sleep(30)

        except Exception as e:
            logger.error(f"Error in continuous_suricata_analysis: {str(e)}")
            time.sleep(60)

            
def process_single_pcap(pcap_file):
    """Helper function to process a single PCAP file"""
    logger.info(f"Processing PCAP: {pcap_file}")
    output_dir = run_suricata_analysis(pcap_file)
    if output_dir:
        alerts = parse_suricata_logs(output_dir)
        if alerts:
            threats = process_suricata_alerts(alerts)
            logger.warning(f"Detected {len(threats['serious_threats'])} serious threats in {pcap_file}")
    return output_dir


def periodic_pcap_threat_detection():
    """Periodically process new PCAP files for threats"""
    while True:
        try:
            current_pcaps = set(f for f in os.listdir(PCAP_DIR) if f.endswith(".pcap"))
            for pcap_file in current_pcaps:
                pcap_path = os.path.join(PCAP_DIR, pcap_file)
                output_dir = run_suricata_analysis(pcap_path)
                if output_dir:
                    alerts = parse_suricata_logs(output_dir)
                    if alerts:
                        threats = process_suricata_alerts(alerts)
                        logger.warning(f"Detected {len(threats)} threats in {pcap_file}")
                        for threat in threats:
                            logger.warning(
                                f"THREAT: {threat['rule_name']} "
                                f"(Severity: {threat['severity']}) - "
                                f"Source: {threat.get('source_ip', 'unknown')}"
                            )
            time.sleep(300)
        except Exception as e:
            logger.error(f"Threat detection error: {str(e)}")
            time.sleep(600)

# Utility functions (keep the same as in zeek.py)
def is_tool_installed(tool):
    return subprocess.run(["which", tool], capture_output=True, text=True).returncode == 0


def load_processed_pcaps():
    if os.path.exists(PROCESSED_PCAPS_JSON):
        try:
            with open(PROCESSED_PCAPS_JSON, 'r') as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                try:
                    content = f.read().strip()
                    return set(json.loads(content)) if content else set()
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
        except Exception as e:
            logger.error(f"Error loading processed PCAPs: {str(e)}")
            return set()
    return set()

def save_processed_pcaps(processed_pcaps):
    temp_file = PROCESSED_PCAPS_JSON + '.tmp'
    with open(temp_file, 'w') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            json.dump(list(processed_pcaps), f)
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    os.replace(temp_file, PROCESSED_PCAPS_JSON)
