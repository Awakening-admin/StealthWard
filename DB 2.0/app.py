import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for
import pyshark
import plotly.express as px
import pandas as pd
from collections import Counter
import subprocess

app = Flask(__name__)

PCAP_DIR = '/home/robot/edr_server/pcap_files/'
BLOCKED_IPS_FILE = '/home/robot/edr_server/blocked_ips.txt'
LOGS_DIR = '/home/robot/edr_server/Logs/'

# Function to process the PCAP file and generate stats
def process_pcap(file_path):
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

# Function to generate plots
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

# Function to get blocked IPs from file
def get_blocked_ips():
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, 'r') as f:
            return [line.strip() for line in f.readlines()]
    return []

# Function to block an IP using ufw or firewalld
def block_ip(ip_address):
    try:
        dist = os.uname().sysname.lower()
        if 'ubuntu' in dist:
            subprocess.run(['sudo', 'ufw', 'deny', 'from', ip_address], check=True)
        elif 'fedora' in dist:
            subprocess.run(['sudo', 'firewall-cmd', '--permanent', '--add-rich-rule', f'rule family="ipv4" source address="{ip_address}" reject'], check=True)
            subprocess.run(['sudo', 'firewall-cmd', '--reload'], check=True)
        with open(BLOCKED_IPS_FILE, 'a') as f:
            f.write(f"{ip_address}\n")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip_address}: {e}")
        return False
    return True

# Preprocess log files (auth.log, syslog, kern.log)
def preprocess_log(log_file_path):
    preprocessed_data = []

    try:
        with open(log_file_path, 'r') as file:
            lines = file.readlines()

        for line in lines:
            # Simple preprocessing: Extract date, log level, and message
            if len(line.strip()) == 0:
                continue
            parts = line.split()
            date = parts[0] + " " + parts[1]
            log_level = parts[2] if len(parts) > 2 else ""
            message = " ".join(parts[3:])

            preprocessed_data.append({
                "date": date,
                "log_level": log_level,
                "message": message
            })
    except Exception as e:
        print(f"Error processing log file {log_file_path}: {e}")

    return preprocessed_data

@app.route('/')
def index():
    pcap_files = [f for f in os.listdir(PCAP_DIR) if f.endswith(".pcap")]
    
    files_with_timestamp = {}
    for file in pcap_files:
        file_path = os.path.join(PCAP_DIR, file)
        timestamp = datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
        files_with_timestamp[file] = timestamp

    grouped_files = {}
    for idx, (file, timestamp) in enumerate(files_with_timestamp.items()):
        ip = file.split('_')[1]
        group_key = f"PC {ip}"
        if group_key not in grouped_files:
            grouped_files[group_key] = []
        grouped_files[group_key].append((file, timestamp))

    return render_template('index.html', pcap_files=grouped_files)

@app.route('/pcap/<file_name>')
def pcap_details(file_name):
    file_path = os.path.join(PCAP_DIR, file_name)
    df, stats = process_pcap(file_path)
    plot_html = generate_plot(df)
    protocol_pie_html = generate_protocol_pie_chart(stats['protocols'])
    ip_stats_html = generate_ip_stats(stats['ip_stats'])
    return render_template('pcap_details.html',
                           file_name=file_name,
                           plot_html=plot_html,
                           protocol_pie_html=protocol_pie_html,
                           ip_stats_html=ip_stats_html,
                           packets_table=stats['packets_table'])

@app.route('/logs')
def logs():
    logs_grouped_by_ip = {}

    # Iterate through all IP folders in the LOGS_DIR
    for ip_folder in os.listdir(LOGS_DIR):
        ip_path = os.path.join(LOGS_DIR, ip_folder)
        
        # Ensure the path is a directory
        if os.path.isdir(ip_path):
            # Include all files in the folder (not just those ending in .log)
            log_files = [f for f in os.listdir(ip_path) if os.path.isfile(os.path.join(ip_path, f))]
            
            # Only add entries with valid log files
            if log_files:
                logs_grouped_by_ip[ip_folder] = log_files

    return render_template('logs.html', logs=logs_grouped_by_ip)

@app.route('/log/<ip>/<log_name>')
def log_details(ip, log_name):
    log_path = os.path.join(LOGS_DIR, ip, log_name)

    if not os.path.exists(log_path):
        return f"Log file {log_name} not found in {ip}.", 404

    preprocessed_data = []
    if log_name in ['filtered_auth.log', 'filtered_syslog', 'filtered_kern.log']:
        preprocessed_data = preprocess_log(log_path)

    return render_template('log_details.html', log_name=log_name, preprocessed_data=preprocessed_data)

@app.route('/blocked_ips', methods=['GET'])
def blocked_ips():
    blocked_ips = get_blocked_ips()
    return render_template('blocked_ips.html', blocked_ips=blocked_ips)

@app.route('/block_ip', methods=['POST'])
def block_ip_route():
    ip = request.form['ip']
    if block_ip(ip):
        return redirect(url_for('blocked_ips'))
    return "Error blocking IP"

if __name__ == '__main__':
    app.run(debug=False)
