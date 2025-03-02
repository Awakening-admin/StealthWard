import os
from datetime import datetime
from flask import Flask, render_template
import pyshark
import plotly.express as px
import pandas as pd
from collections import Counter

app = Flask(__name__)

PCAP_DIR = '/home/robot/edr_server/pcap_files/'

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

@app.route('/')
def index():
    # Grouping files dynamically
    pcap_files = [f for f in os.listdir(PCAP_DIR) if f.endswith(".pcap")]
    
    files_with_timestamp = {}
    for file in pcap_files:
        file_path = os.path.join(PCAP_DIR, file)
        timestamp = datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
        files_with_timestamp[file] = timestamp
    
    # Dynamically group the files
    grouped_files = {}
    for idx, (file, timestamp) in enumerate(files_with_timestamp.items()):
        group_key = f"PC {idx + 1}"
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

if __name__ == '__main__':
    app.run(debug=False)  # Turn off debug mode
