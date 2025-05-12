import os
import pandas as pd
import json
import pyshark
from collections import Counter
import plotly.express as px
import logging
import subprocess

# Directory paths
LOGS_DIR = '/home/robot/edr_server/Logs/'
PCAP_DIR = '/home/robot/edr_server/pcap_files/'
BLOCKED_IPS_JSON = '/home/robot/edr_server/blocked_ips.json'
THREATS_JSON = '/home/robot/edr_server/threats.json'
CLAMAV_RESULTS_JSON = '/home/robot/edr_server/clamav_results.json'
IDS_PCAP_ALERTS_JSON = '/home/robot/edr_server/ids_pcap_alerts.json'
ADMIN_LOG_ALERTS_JSON = '/home/robot/edr_server/ids_admin_log_alerts.json'
NETWORK_THREATS_JSON = '/home/robot/edr_server/network_threats.json'
DETECTION_LOG = '/home/robot/edr_server/detection.log'

# Create directories if they don't exist
os.makedirs(LOGS_DIR, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=DETECTION_LOG
)
logger = logging.getLogger(__name__)

def process_pcap(file_path):
    capture = pyshark.FileCapture(file_path, use_json=True)
    packets_data = []
    ip_stats = Counter()
    protocols = Counter()

    for packet in capture:
        try:
            # Initialize with default values
            packet_info = {
                "time": None,
                "source": None,
                "destination": None,
                "protocol": "Unknown",
                "length": 0,
            }

            # Get basic packet info
            if hasattr(packet, 'sniff_time'):
                packet_info["time"] = packet.sniff_time
            if hasattr(packet, 'length'):
                packet_info["length"] = int(packet.length)

            # Try to get source/destination from different layers
            for layer in ['ip', 'ipv6', 'arp', 'eth']:
                if hasattr(packet, layer):
                    layer_obj = getattr(packet, layer)
                    if not packet_info["source"] and hasattr(layer_obj, 'src'):
                        packet_info["source"] = layer_obj.src
                    if not packet_info["destination"] and hasattr(layer_obj, 'dst'):
                        packet_info["destination"] = layer_obj.dst

            # Protocol detection - check multiple layers
            protocol = None
            for layer in ['transport_layer', 'highest_layer', 'frame_info']:
                if hasattr(packet, layer):
                    layer_obj = getattr(packet, layer)
                    if layer == 'transport_layer' and layer_obj:
                        protocol = str(layer_obj)
                        break
                    elif layer == 'highest_layer' and layer_obj:
                        protocol = str(layer_obj).lower()
                        break
                    elif layer == 'frame_info' and hasattr(layer_obj, 'protocol'):
                        protocol = str(layer_obj.protocol)
                        break

            if protocol:
                packet_info["protocol"] = protocol

            packets_data.append(packet_info)
            
            # Update statistics
            if packet_info["source"] and packet_info["destination"]:
                ip_stats[(packet_info["source"], packet_info["destination"])] += 1
            
            protocols[packet_info["protocol"]] += 1
            
        except Exception as e:
            logger.warning(f"Error processing packet: {str(e)}")
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
    fig = px.line(df, x='time', y='length', title='Packet Length Over Time')
    return fig.to_html(full_html=False)

def generate_protocol_pie_chart(protocols):
    labels = list(protocols.keys())
    values = list(protocols.values())
    fig = px.pie(names=labels, values=values, title='Protocol Distribution')
    return fig.to_html(full_html=False)

def generate_ip_stats(ip_stats):
    data = {
        "Source IP": [ip[0] for ip in ip_stats.keys()],
        "Destination IP": [ip[1] for ip in ip_stats.keys()],
        "Packets": list(ip_stats.values())
    }
    df = pd.DataFrame(data)
    fig = px.bar(df, x='Source IP', y='Packets', color='Destination IP', title='IP Statistics')
    return fig.to_html(full_html=False)

def is_tool_installed(tool):
    return subprocess.run(["which", tool], capture_output=True, text=True).returncode == 0

def ensure_blocked_ips_file():
    if not os.path.exists(BLOCKED_IPS_JSON):
        with open(BLOCKED_IPS_JSON, 'w') as f:
            json.dump([], f, indent=4)

def get_blocked_ips():
    ensure_blocked_ips_file()
    with open(BLOCKED_IPS_JSON, 'r') as f:
        return json.load(f)

def update_blocked_ips(blocked_ips):
    ensure_blocked_ips_file()
    with open(BLOCKED_IPS_JSON, 'w') as f:
        json.dump(blocked_ips, f, indent=4)

def check_system_dependencies():
    checks = {
        'pyshark': ['tshark', '--version']
    }

    results = {}
    for name, cmd in checks.items():
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            results[name] = {
                'installed': result.returncode == 0,
                'version': result.stdout.split('\n')[0] if result.stdout else 'Unknown'
            }
        except Exception as e:
            results[name] = {'installed': False, 'error': str(e)}

    return results

def load_threats():
    if os.path.exists(THREATS_JSON):
        try:
            with open(THREATS_JSON, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading threats: {str(e)}")
    return []

def load_clamav_results():
    if os.path.exists(CLAMAV_RESULTS_JSON):
        try:
            with open(CLAMAV_RESULTS_JSON, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading ClamAV results: {str(e)}")
    return []

def load_pcap_alerts():
    if os.path.exists(IDS_PCAP_ALERTS_JSON):
        try:
            with open(IDS_PCAP_ALERTS_JSON, 'r') as f:
                alerts = json.load(f)
                if isinstance(alerts, list):
                    return alerts
        except Exception as e:
            logger.error(f"Error loading PCAP alerts: {str(e)}")
    return []

def load_admin_log_alerts():
    if os.path.exists(ADMIN_LOG_ALERTS_JSON):
        try:
            with open(ADMIN_LOG_ALERTS_JSON, 'r') as f:
                alerts = json.load(f)
                if isinstance(alerts, list):
                    return alerts
        except Exception as e:
            logger.error(f"Error loading admin log alerts: {str(e)}")
    return []

def load_network_threats():
    if os.path.exists(NETWORK_THREATS_JSON):
        try:
            with open(NETWORK_THREATS_JSON, 'r') as f:
                threats = json.load(f)
                if isinstance(threats, list):
                    return threats
        except Exception as e:
            logger.error(f"Error loading network threats: {str(e)}")
    return []

def load_endpoint_alerts():
    alerts_dir = '/home/robot/edr_server/alerts/'
    all_alerts = []

    if not os.path.exists(alerts_dir):
        logger.error(f"Alerts directory not found: {alerts_dir}")
        return all_alerts

    try:
        alert_files = [f for f in os.listdir(alerts_dir) if f.endswith('.json')]

        for alert_file in alert_files:
            try:
                with open(os.path.join(alerts_dir, alert_file), 'r') as f:
                    alerts = json.load(f)
                    if isinstance(alerts, list):
                        # Convert endpoint alert format to match existing pcap alert format
                        for alert in alerts:
                            normalized_alert = {
                                'timestamp': alert.get('timestamp'),
                                'source_ip': alert.get('source_ip'),
                                'dest_ip': alert.get('destination_ip'),
                                'src_port': alert.get('source_port'),
                                'dst_port': alert.get('destination_port'),
                                'severity': alert.get('severity', 'medium'),
                                'rule_msg': alert.get('attack_type', 'Unknown Attack'),
                                'rule_sid': hash(alert.get('attack_type', '')) % 1000000,
                                'protocol': 'TCP',  # Assuming SSH is TCP
                                'pcap_info': {
                                    'src_port': alert.get('source_port'),
                                    'dst_port': alert.get('destination_port'),
                                    'file_path': alert.get('pcap_reference', '')
                                }
                            }
                            all_alerts.append(normalized_alert)
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON in {alert_file}: {str(e)}")
            except Exception as e:
                logger.error(f"Error processing alert file {alert_file}: {str(e)}")

    except Exception as e:
        logger.error(f"Error listing alert files: {str(e)}")

    return all_alerts
