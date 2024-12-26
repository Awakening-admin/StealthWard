import os
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for
import pyshark
import plotly.express as px
import pandas as pd
from collections import Counter

app = Flask(__name__)

PCAP_DIR = '/home/arslan/edr_server/pcap_files/'
BLOCKED_IPS_JSON = '/home/arslan/edr_server/blocked_ips.json'
LOGS_DIR = '/home/arslan/edr_server/Logs/'

# Ensure the blocked_ips.json file exists
def ensure_blocked_ips_file():
    if not os.path.exists(BLOCKED_IPS_JSON):
        with open(BLOCKED_IPS_JSON, 'w') as f:
            json.dump([], f, indent=4)

# Function to get blocked IPs from JSON file
def get_blocked_ips():
    ensure_blocked_ips_file()  # Ensure the file exists
    with open(BLOCKED_IPS_JSON, 'r') as f:
        return json.load(f)

# Function to update the blocked IPs JSON file
def update_blocked_ips(blocked_ips):
    ensure_blocked_ips_file()  # Ensure the file exists
    with open(BLOCKED_IPS_JSON, 'w') as f:
        json.dump(blocked_ips, f, indent=4)

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

@app.route('/block_ip', methods=['POST'])
def block_ip():
    ip_to_block = request.form.get('ip')
    if ip_to_block:
        blocked_ips = get_blocked_ips()
        if ip_to_block not in blocked_ips:
            blocked_ips.append(ip_to_block)
            update_blocked_ips(blocked_ips)
        return redirect(url_for('blocked_ips'))
    return "Invalid IP address", 400

@app.route('/unblock_ip/<ip>', methods=['POST'])
def unblock_ip(ip):
    blocked_ips = get_blocked_ips()
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        update_blocked_ips(blocked_ips)
    return redirect(url_for('blocked_ips'))

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

    for ip_folder in os.listdir(LOGS_DIR):
        ip_path = os.path.join(LOGS_DIR, ip_folder)
        if os.path.isdir(ip_path):
            log_files = [f for f in os.listdir(ip_path) if os.path.isfile(os.path.join(ip_path, f))]
            if log_files:
                logs_grouped_by_ip[ip_folder] = log_files

    return render_template('logs.html', logs=logs_grouped_by_ip)

@app.route('/log/<ip>/<log_name>')
def log_details(ip, log_name):
    log_path = os.path.join(LOGS_DIR, ip, log_name)
    if not os.path.exists(log_path):
        return f"Log file {log_name} not found in {ip}.", 404

    preprocessed_data = preprocess_log(log_path)

    return render_template('log_details.html', log_name=log_name, preprocessed_data=preprocessed_data)
    
@app.route('/blocked_ips', methods=['GET'])
def blocked_ips():
    blocked_ips = get_blocked_ips()
    return render_template('blocked_ips.html', blocked_ips=blocked_ips)

# Preprocess log files to handle any logs sent by the agent
def preprocess_log(log_file_path):
    preprocessed_data = []

    try:
        with open(log_file_path, 'r') as file:
            lines = file.readlines()
        for line in lines:
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



@app.route('/statistics')
def statistics():
    # Load log stats from log_stats.json
    try:
        with open('/home/robot/edr_server/log_stats.json', 'r') as f:
            log_stats = json.load(f)
    except Exception as e:
        log_stats = []

    # Load pcap stats from pcap_stats.json
    try:
        with open('/home/robot/edr_server/pcap_stats.json', 'r') as f:
            pcap_stats = json.load(f)
    except Exception as e:
        pcap_stats = []

    # Calculate additional statistics (packet count, avg packet size, peak traffic)
    stats_data = calculate_network_stats(pcap_stats)

    return render_template('statistics.html', log_stats=log_stats, pcap_stats=pcap_stats, stats_data=stats_data)

def calculate_network_stats(pcap_stats):
    packet_count = sum(stat['packet_count'] for stat in pcap_stats)
    total_size = sum(stat['total_size'] for stat in pcap_stats)
    average_packet_size = total_size / packet_count if packet_count else 0

    peak_traffic = max(stat['packet_count'] for stat in pcap_stats) if pcap_stats else 0

    return {
        'packet_count': packet_count,
        'average_packet_size': average_packet_size,
        'peak_traffic': peak_traffic
    }
   

if __name__ == '__main__':
    ensure_blocked_ips_file()
    app.run(debug=False)
