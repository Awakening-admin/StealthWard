from flask import Flask, render_template, request, redirect, url_for, jsonify, flash , send_file
import os
import json
import signal
import sys
import logging
from datetime import datetime
import pandas as pd
import plotly.express as px
import ipaddress
import subprocess
from admin import run_admin_monitor
from babel.numbers import format_number
from utils import (
    LOGS_DIR,
    PCAP_DIR,
    BLOCKED_IPS_JSON,
    process_pcap,
    generate_plot,
    generate_protocol_pie_chart,
    generate_ip_stats,
    is_tool_installed,
    check_system_dependencies,
    logger,
    load_threats,
    load_clamav_results,
    load_pcap_alerts,
    load_admin_log_alerts,
    load_network_threats,
    load_endpoint_alerts
)

app = Flask(__name__)
app.config['INVENTORY_PATH'] = '/home/robot/Desktop/AgentWAnsible/inventory.ini'
app.secret_key = 'your-secret-key-here'  # Required for flash messages

admin_monitor = run_admin_monitor()

# Initialize blocked_ips.json if it doesn't exist
if not os.path.exists(BLOCKED_IPS_JSON):
    with open(BLOCKED_IPS_JSON, 'w') as f:
        json.dump([], f)

@app.template_filter('basename')
def basename_filter(path):
    return os.path.basename(path)

@app.template_filter('intcomma')
def intcomma_filter(value):
    try:
        return format_number(value, locale='en_US')
    except:
        return str(value)

# Configure logging
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/home/robot/edr_server/app.log'),
            logging.StreamHandler()
        ]
    )
logger = logging.getLogger(__name__)

def run_ansible_playbook():
    """Execute the Ansible playbook to distribute blocked_ips.json"""
    playbook_path = '/home/robot/Desktop/AgentWAnsible/update_blocked_ips.yml'
    inventory_path = app.config['INVENTORY_PATH']

    try:
        result = subprocess.run(
            ['ansible-playbook', '-i', inventory_path, playbook_path],
            capture_output=True,
            text=True,
            check=True
        )
        logger.info(f"Ansible playbook executed successfully:\n{result.stdout}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Ansible playbook failed:\n{e.stderr}")
        return False

def get_blocked_ips():
    """Read blocked IPs from JSON file"""
    try:
        with open(BLOCKED_IPS_JSON, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to read {BLOCKED_IPS_JSON}: {str(e)}")
        return []

def update_blocked_ips(ip_list):
    """Update blocked_ips.json with new IP list"""
    try:
        with open(BLOCKED_IPS_JSON, 'w') as f:
            json.dump(ip_list, f)
        logger.info(f"Updated {BLOCKED_IPS_JSON}")
        return True
    except Exception as e:
        logger.error(f"Failed to update {BLOCKED_IPS_JSON}: {str(e)}")
        return False

@app.route('/')
def index():
    try:
        if not os.path.exists(PCAP_DIR):
            logger.error(f"PCAP directory not found: {PCAP_DIR}")
            return render_template('error.html', message="PCAP directory not found"), 500

        try:
            pcap_files = [f for f in os.listdir(PCAP_DIR) if f.endswith(".pcap")]
            logger.info(f"Found {len(pcap_files)} PCAP files")
        except Exception as e:
            logger.error(f"Failed to list PCAP files: {str(e)}")
            return render_template('error.html', message="Failed to list PCAP files"), 500

        files_with_timestamp = {}
        for file in pcap_files:
            try:
                file_path = os.path.join(PCAP_DIR, file)
                timestamp = datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                files_with_timestamp[file] = timestamp
            except Exception as e:
                logger.error(f"Failed to process file {file}: {str(e)}")
                continue

        grouped_files = {}
        for file, timestamp in files_with_timestamp.items():
            try:
                parts = file.split('_')
                if len(parts) >= 2:
                    ip = parts[1]
                else:
                    ip = "unknown"

                group_key = f"PC {ip}"
                if group_key not in grouped_files:
                    grouped_files[group_key] = []
                grouped_files[group_key].append((file, timestamp))
            except Exception as e:
                logger.error(f"Failed to group file {file}: {str(e)}")
                continue

        return render_template('index.html', pcap_files=grouped_files)

    except Exception as e:
        logger.error(f"Unexpected error in index route: {str(e)}", exc_info=True)
        return render_template('error.html', message="Internal Server Error"), 500

@app.route('/pcap/<file_name>')
def pcap_details(file_name):
    try:
        file_path = os.path.join(PCAP_DIR, file_name)

        if not os.path.exists(file_path):
            return "PCAP file not found", 404

        try:
            df, stats = process_pcap(file_path)
        except Exception as e:
            return f"Error processing PCAP: {str(e)}", 500

        return render_template('pcap_details.html',
            file_name=file_name,
            plot_html=generate_plot(df),
            protocol_pie_html=generate_protocol_pie_chart(stats['protocols']),
            ip_stats_html=generate_ip_stats(stats['ip_stats']),
            packets_table=stats['packets_table']
        )
    except Exception as e:
        return f"Unexpected error: {str(e)}", 500

@app.route('/alerts')
def alerts():
    # Load and process log-based threats
    raw_threats = load_threats()

    # Load and process network threats from both sources
    raw_pcap_threats = load_pcap_alerts()
    endpoint_alerts = load_endpoint_alerts()
    all_network_threats = raw_pcap_threats + endpoint_alerts

    # Process network threats to group similar ones
    processed_network_threats = []
    seen_threats = {}

    for threat in all_network_threats:
        threat_key = (
            f"{threat.get('source_ip', 'unknown')}-"
            f"{threat.get('dest_ip', 'unknown')}-"
            f"{threat.get('rule_msg', 'unknown')}-"
            f"{threat.get('src_port', 'unknown')}-"
            f"{threat.get('dst_port', 'unknown')}"
        )

        if threat_key in seen_threats:
            seen_threats[threat_key]['count'] += 1
            if threat.get('timestamp', '') > seen_threats[threat_key].get('timestamp', ''):
                seen_threats[threat_key]['timestamp'] = threat['timestamp']
        else:
            threat['count'] = 1
            threat['is_duplicate'] = False
            seen_threats[threat_key] = threat
            processed_network_threats.append(threat)

    # Separate minor alerts (medium/low severity)
    minor_alerts = [t for t in processed_network_threats if t.get('severity', 'medium') in ['medium', 'low']]
    minor_network_alerts = minor_alerts[-20:]

    return render_template(
        'alerts.html',
        threats=raw_threats,
        pcap_threats=processed_network_threats,
        minor_network_alerts=minor_network_alerts
    )


# Add this new route to your existing app.py
@app.route('/api/generate_report', methods=['POST'])
def generate_report():
    try:
        report_path = admin_monitor.generate_report()
        if report_path:
            return jsonify({
                'success': True,
                'message': 'Report generated successfully',
                'report_path': report_path
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to generate report'
            }), 500
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error generating report: {str(e)}'
        }), 500

# Add this to your app.py
@app.route('/api/list_reports')
def list_reports():
    try:
        reports_dir = '/home/robot/edr_server/reports'
        if not os.path.exists(reports_dir):
            return jsonify({'reports': []})
            
        reports = []
        for filename in sorted(os.listdir(reports_dir), reverse=True):
            if filename.endswith('.pdf'):
                filepath = os.path.join(reports_dir, filename)
                stats = os.stat(filepath)
                reports.append({
                    'name': filename,
                    'path': filepath,
                    'size': f"{(stats.st_size / 1024):.1f} KB",
                    'date': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M')
                })
                
        return jsonify({'reports': reports[:10]})  # Return only the 10 most recent reports
    except Exception as e:
        logger.error(f"Error listing reports: {str(e)}")
        return jsonify({'reports': []})

@app.route('/reports/<filename>')
def download_report(filename):
    reports_dir = '/home/robot/edr_server/reports'
    filepath = os.path.join(reports_dir, filename)
    
    if not os.path.exists(filepath):
        return "Report not found", 404
        
    # Open the PDF in the browser instead of downloading
    return send_file(filepath, as_attachment=False)



@app.route('/get_alert_ids')
def get_alert_ids():
    try:
        threats = load_threats()
        pcap_threats = load_pcap_alerts()

        alert_ids = []
        for threat in threats:
            try:
                alert_id = f"log-{threat.get('ip', 'unknown')}-{hash(threat.get('message', '')) % 1000000}"
                alert_ids.append(alert_id)
            except Exception as e:
                logger.error(f"Error generating alert ID for threat: {e}")

        for pcap_threat in pcap_threats:
            try:
                alert_id = f"pcap-{pcap_threat.get('source_ip', 'unknown')}-{hash(pcap_threat.get('description', '')) % 1000000}"
                alert_ids.append(alert_id)
            except Exception as e:
                logger.error(f"Error generating alert ID for pcap threat: {e}")

        return jsonify({'alert_ids': alert_ids})

    except Exception as e:
        logger.error(f"Error in get_alert_ids: {str(e)}", exc_info=True)
        return jsonify({'alert_ids': []}), 500

@app.route('/block_ip', methods=['POST'])
def block_ip():
    ip_to_block = request.form.get('ip')
    if not ip_to_block:
        flash('IP address is required', 'error')
        return redirect(url_for('blocked_ips'))

    # Validate IP address
    try:
        ipaddress.ip_address(ip_to_block)
    except ValueError:
        flash('Invalid IP address format', 'error')
        return redirect(url_for('blocked_ips'))

    # Get current blocked IPs
    blocked_ips = get_blocked_ips()

    # Check if already blocked
    if ip_to_block in blocked_ips:
        flash('IP is already blocked', 'warning')
        return redirect(url_for('blocked_ips'))

    # Add to blocked IPs
    blocked_ips.append(ip_to_block)

    # Update JSON file
    if update_blocked_ips(blocked_ips):
        # Run Ansible playbook
        if run_ansible_playbook():
            flash(f'IP {ip_to_block} blocked successfully and distributed to endpoints', 'success')
        else:
            flash(f'IP {ip_to_block} blocked but failed to distribute to endpoints', 'warning')
    else:
        flash('Failed to update blocked IPs file', 'error')

    return redirect(url_for('blocked_ips'))

@app.route('/unblock_ip/<ip>', methods=['POST'])
def unblock_ip(ip):
    # Get current blocked IPs
    blocked_ips = get_blocked_ips()

    # Check if IP is in blocked list
    if ip not in blocked_ips:
        flash('IP not found in blocked list', 'error')
        return redirect(url_for('blocked_ips'))

    # Remove from blocked IPs
    blocked_ips.remove(ip)

    # Update JSON file
    if update_blocked_ips(blocked_ips):
        # Run Ansible playbook
        if run_ansible_playbook():
            flash(f'IP {ip} unblocked successfully and changes distributed to endpoints', 'success')
        else:
            flash(f'IP {ip} unblocked but failed to distribute changes to endpoints', 'warning')
    else:
        flash('Failed to update blocked IPs file', 'error')

    return redirect(url_for('blocked_ips'))

@app.route('/blocked_ips', methods=['GET'])
def blocked_ips():
    blocked_ips = get_blocked_ips()
    return render_template('blocked_ips.html', blocked_ips=blocked_ips)

@app.route('/api/admin_monitoring')
def admin_monitoring_api():
    try:
        return jsonify(admin_monitor.get_current_data())
    except Exception as e:
        logger.error(f"Error in admin monitoring API: {str(e)}")
        return jsonify({'error': 'Failed to load monitoring data'}), 500

@app.route('/admin')
def admin_monitoring():
    try:
        interface_status = {
            'current_interface': admin_monitor.current_interface,
            'is_running': admin_monitor.running,
            'last_analysis': admin_monitor.last_analysis
        }

        data = admin_monitor.get_current_data()

        # Load admin-specific threats
        admin_threats = load_admin_log_alerts()
        network_threats = load_network_threats()

        return render_template(
            'admin.html',
            threats=admin_threats,
            alerts=network_threats,
            status=interface_status
        )
    except Exception as e:
        logger.error(f"Error loading admin monitoring data: {str(e)}")
        return render_template('error.html', message="Failed to load admin monitoring data"), 500

@app.route('/statistics')
def statistics():
    try:
        stats_file = '/home/robot/edr_server/stats_cache.json'

        # Load default structure from pystats.py's _default_stats()
        stats_data = {
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
            'log_stats': [],
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

        # Load and merge cache data if exists
        if os.path.exists(stats_file):
            try:
                with open(stats_file, 'r') as f:
                    cached_stats = json.load(f)

                    # Deep merge for each section
                    for section in ['network_stats', 'threat_stats', 'endpoint_stats']:
                        if section in cached_stats:
                            stats_data[section].update(cached_stats[section])

                    # Handle lists
                    stats_data['log_stats'] = cached_stats.get('log_stats', [])

                    # Handle all visualizations
                    for viz in stats_data['visualizations']:
                        stats_data['visualizations'][viz] = cached_stats.get('visualizations', {}).get(viz, '')

            except Exception as e:
                logger.error(f"Error loading stats cache: {str(e)}")

        # Prepare the data for template exactly as statistics.html expects
        return render_template(
            'statistics.html',
            network_stats=stats_data['network_stats'],
            threat_stats=stats_data['threat_stats'],
            endpoint_stats=stats_data['endpoint_stats'],
            log_stats=stats_data['log_stats'],
            visualizations=stats_data['visualizations']
        )

    except Exception as e:
        logger.error(f"Error in statistics route: {str(e)}", exc_info=True)
        return render_template('error.html', message="Failed to load statistics"), 500

def generate_protocol_chart(protocol_data):
    try:
        df = pd.DataFrame(protocol_data, columns=['Protocol', 'Count'])
        if df.empty:
            df = pd.DataFrame([['http', 1], ['dns', 1]], columns=['Protocol', 'Count'])

        fig = px.pie(df, values='Count', names='Protocol',
                    title='Network Protocols Distribution',
                    color_discrete_sequence=px.colors.sequential.RdBu)
        fig.update_traces(textposition='inside', textinfo='percent+label')
        return fig.to_html(full_html=False)
    except Exception as e:
        logger.error(f"Failed to generate protocol chart: {e}")
        return "<div class='empty-state'><p>Protocol data not available</p></div>"

def generate_ip_traffic_chart(ip_data):
    try:
        df = pd.DataFrame(ip_data, columns=['IP', 'Traffic'])
        if df.empty:
            df = pd.DataFrame([['127.0.0.1', 1]], columns=['IP', 'Traffic'])

        fig = px.bar(df, x='IP', y='Traffic',
                    title='Top IP Traffic Sources',
                    color='Traffic',
                    color_continuous_scale='Viridis')
        fig.update_layout(xaxis_title='IP Address', yaxis_title='Packets')
        return fig.to_html(full_html=False)
    except Exception as e:
        logger.error(f"Failed to generate IP traffic chart: {e}")
        return "<div class='empty-state'><p>IP traffic data not available</p></div>"

@app.route('/logs')
def logs():
    logs_grouped_by_ip = {}
    try:
        ip_folders = [d for d in os.listdir(LOGS_DIR)
                     if os.path.isdir(os.path.join(LOGS_DIR, d))]

        for ip_folder in ip_folders:
            ip_path = os.path.join(LOGS_DIR, ip_folder)
            try:
                log_files = [f for f in os.listdir(ip_path)
                           if os.path.isfile(os.path.join(ip_path, f)) and f.endswith('.log')]
                log_files.sort(key=lambda f: os.path.getmtime(os.path.join(ip_path, f)), reverse=True)

                if log_files:
                    logs_grouped_by_ip[ip_folder] = log_files
            except Exception as e:
                logger.error(f"Error processing IP folder {ip_folder}: {e}")
                continue

    except Exception as e:
        logger.error(f"Error listing log directories: {e}")

    return render_template('logs.html', logs=logs_grouped_by_ip)

@app.route('/log/<ip>/<log_name>')
def log_details(ip, log_name):
    log_path = os.path.join(LOGS_DIR, ip, log_name)
    if not os.path.exists(log_path):
        return f"Log file {log_name} not found in {ip}.", 404

    try:
        preprocessed_data = preprocess_log(log_path, log_name)
        return render_template('log_details.html',
                            log_name=log_name,
                            preprocessed_data=preprocessed_data,
                            ip=ip)
    except Exception as e:
        logger.error(f"Error processing log {log_name}: {e}")
        return render_template('error.html',
                            message=f"Error processing log file: {str(e)}"), 500

def preprocess_log(log_file_path, log_name):
    preprocessed_data = []

    try:
        with open(log_file_path, 'r') as file:
            lines = file.readlines()

            if log_name in ['dhcp.log', 'http.log', 'ssl.log', 'ssh.log', 'ftp.log']:
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue

                    if ' ' in line and ':' in line.split(' ')[1]:
                        parts = line.split(' ', 2)
                        if len(parts) >= 3:
                            date_time = f"{parts[0]} {parts[1]}"
                            message = parts[2]
                        else:
                            date_time = ""
                            message = line
                    else:
                        date_time = ""
                        message = line

                    preprocessed_data.append({
                        "date": date_time,
                        "log_level": "INFO",
                        "message": message
                    })

            elif log_name in ['filtered_auth.log', 'filtered_syslog']:
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue

                    parts = line.split(maxsplit=3)
                    if len(parts) >= 4:
                        preprocessed_data.append({
                            "date": f"{parts[0]} {parts[1]}",
                            "log_level": parts[2],
                            "message": parts[3]
                        })
                    else:
                        preprocessed_data.append({
                            "date": "",
                            "log_level": "INFO",
                            "message": line
                        })

            preprocessed_data.sort(key=lambda x: x['date'], reverse=True)

    except Exception as e:
        logger.error(f"Error processing log file {log_file_path}: {e}")
        preprocessed_data.append({
            "date": "",
            "log_level": "ERROR",
            "message": f"Error processing log file: {str(e)}"
        })

    return preprocessed_data

def shutdown_handler(signum, frame):
    logger.info("Shutting down server...")
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    deps = check_system_dependencies()
    logger.info("=== System Dependencies ===")
    for name, info in deps.items():
        status = "OK" if info.get('installed') else "MISSING"
        logger.info(f"{name.upper():<10} {status:<8} {info.get('version', '')}")

    if not all(info['installed'] for info in deps.values()):
        logger.warning("Some dependencies are missing. Functionality will be limited.")

    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        shutdown_handler(None, None)
