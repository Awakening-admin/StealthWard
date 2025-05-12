from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_file
import os
import json
from collections import defaultdict
import signal
import sys
import logging
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
import ipaddress
import subprocess
import requests
from admin import run_admin_monitor
from babel.numbers import format_number
from utils import (
    fetch_mitre_techniques,
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
    load_endpoint_alerts,
    preprocess_log
)

app = Flask(__name__)
app.config['INVENTORY_PATH'] = '/home/robot/Downloads/Agent/inventoryy.ini'
app.secret_key = 'your-secret-key-here'

# Cache for MITRE techniques (refresh every 24 hours)
MITRE_TECHNIQUES = {}
MITRE_LAST_UPDATED = None

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
    playbook_path = '/home/robot/Downloads/Agent/update_blocked_ips.yml'
    inventory_path = app.config['INVENTORY_PATH']

    try:
        with open('/home/robot/edr_server/blocked_ips.json') as f:
            json.load(f)

        result = subprocess.run(
            ['ansible-playbook', '-i', inventory_path, playbook_path],
            capture_output=True,
            text=True,
            check=True
        )
        logger.info(f"Ansible playbook executed successfully:\n{result.stdout}")
        return True
    except Exception as e:
        logger.error(f"Error running playbook: {str(e)}")
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

def fetch_mitre_techniques():
    """Fetch MITRE techniques from API with caching"""
    global MITRE_TECHNIQUES, MITRE_LAST_UPDATED
    
    # Return cached data if recent
    if MITRE_LAST_UPDATED and (datetime.now() - MITRE_LAST_UPDATED) < timedelta(hours=24):
        return MITRE_TECHNIQUES
    
    try:
        response = requests.get('https://attack.mitre.org/api.php?action=ask&query=[[Category:Technique]]&format=json')
        if response.status_code == 200:
            data = response.json()
            techniques = {}
            
            for tech_id, tech_data in data.get('query', {}).get('results', {}).items():
                techniques[tech_id] = {
                    'name': tech_data.get('fulltext', tech_id),
                    'description': tech_data.get('description', 'No description available'),
                    'url': f'https://attack.mitre.org/techniques/{tech_id}/'
                }
            
            MITRE_TECHNIQUES = techniques
            MITRE_LAST_UPDATED = datetime.now()
            return techniques
    except Exception as e:
        logger.error(f"Error fetching MITRE techniques: {str(e)}")
    
    return MITRE_TECHNIQUES

def analyze_threats(threats):
    """Analyze threats and provide actionable insights with MITRE mappings"""
    insights = {
        'critical_threats': [],
        'common_techniques': defaultdict(int),
        'top_sources': defaultdict(int),
        'recommendations': [],
        'stats': {
            'total': len(threats),
            'by_severity': defaultdict(int),
            'by_type': defaultdict(int),
            'by_mitre_tactic': defaultdict(int)
        },
        'mitre_techniques': defaultdict(int)
    }
    
    if not threats:
        return insights
    
    # Get MITRE techniques in real-time
    mitre_techniques = fetch_mitre_techniques()
    
    # Technique mappings based on threat patterns
    technique_mappings = {
        'bruteforce': 'T1110',
        'brute force': 'T1110',
        'scan': 'T1595',
        'scanning': 'T1595',
        'port scan': 'T1595',
        'injection': 'T1059',
        'sql injection': 'T1190',
        'malware': 'T1204',
        'ransomware': 'T1486',
        'lateral': 'T1021',
        'lateral movement': 'T1021',
        'privilege': 'T1068',
        'privilege escalation': 'T1068',
        'credential': 'T1003',
        'credential dumping': 'T1003',
        'persistence': 'T1136',
        'defense evasion': 'T1070',
        'discovery': 'T1018',
        'execution': 'T1059',
        'collection': 'T1119',
        'exfiltration': 'T1020',
        'command and control': 'T1071',
        'c2': 'T1071',
        'impact': 'T1489',
        'denial of service': 'T1498',
        'dos': 'T1498',
        'phishing': 'T1566',
        'spoofing': 'T1556',
        'exploit': 'T1210',
        'vulnerability': 'T1210',
        'backdoor': 'T1133',
        'scheduled task': 'T1053',
        'registry': 'T1112',
        'process injection': 'T1055'
    }

    # In analyze_threats(), improve the MITRE technique mapping logic:
    for threat in threats:
        # Normalize the attack type and message
        attack_type = str(threat.get('attack_type', threat.get('rule_msg', threat.get('description', 'unknown')))).lower()
        msg = str(threat.get('message', '')).lower()
        severity = threat.get('severity', 'medium').lower()
        source_ip = threat.get('source_ip', threat.get('src_ip', 'unknown'))
        
        # Initialize MITRE technique as unknown
        mitre_id = None
        mitre_name = "Unknown"
        
        # First try direct mappings from normalized attack type
        for pattern, tech_id in technique_mappings.items():
            if pattern in attack_type:
                mitre_id = tech_id
                mitre_data = mitre_techniques.get(tech_id, {})
                mitre_name = mitre_data.get('name', tech_id)
                break
        
        # If no direct mapping, try to find in message content
        if not mitre_id:
            for pattern, tech_id in technique_mappings.items():
                if pattern in msg:
                    mitre_id = tech_id
                    mitre_data = mitre_techniques.get(tech_id, {})
                    mitre_name = mitre_data.get('name', tech_id)
                    break
        
        # If still no mapping, try to match against MITRE technique names
        if not mitre_id:
            for tech_id, tech_data in mitre_techniques.items():
                tech_name = tech_data.get('name', '').lower()
                if tech_name in attack_type or tech_name in msg:
                    mitre_id = tech_id
                    mitre_name = tech_data.get('name', tech_id)
                    break
        
        # If all else fails, use a default technique based on severity
        if not mitre_id:
            if severity == 'critical':
                mitre_id = 'T1190'
                mitre_name = 'Exploit Public-Facing Application'
            elif severity == 'high':
                mitre_id = 'T1059'
                mitre_name = 'Command-Line Interface'
        
        # Update insights
        if mitre_id:
            insights['mitre_techniques'][(mitre_id, mitre_name)] += 1
            # Get tactics for this technique
            tactics = mitre_techniques.get(mitre_id, {}).get('tactics', [])
            for tactic in tactics:
                insights['stats']['by_mitre_tactic'][tactic] += 1
        
        # Clean up the attack type for display
        attack_type = attack_type.replace('_', ' ').title()
        if mitre_name != "Unknown":
            attack_type = f"{attack_type} ({mitre_name})"
        
        # Update stats
        insights['stats']['by_severity'][severity] += 1
        insights['stats']['by_type'][attack_type] += 1
        insights['top_sources'][source_ip] += 1
        
        # Track critical threats
        if severity in ['critical', 'high']:
            insights['critical_threats'].append({
                'source': source_ip,
                'type': attack_type,
                'message': threat.get('message', 'No details'),
                'timestamp': threat.get('timestamp', 'Unknown time'),
                'severity': severity,
                'mitre_id': mitre_id,
                'mitre_name': mitre_name
            })
    
    # Generate recommendations
    if insights['stats']['by_severity'].get('critical', 0) > 0:
        insights['recommendations'].append({
            'title': 'Critical Threats Detected',
            'description': f"{insights['stats']['by_severity'].get('critical', 0)} critical threats require immediate attention",
            'action': 'Isolate affected systems and investigate root cause',
            'priority': 'critical',
            'techniques': ['T1059', 'T1204']
        })
    
    if insights['top_sources']:
        top_ip, top_count = next(iter(sorted(insights['top_sources'].items(), key=lambda x: x[1], reverse=True)))
        insights['recommendations'].append({
            'title': 'Frequent Threat Source',
            'description': f"IP {top_ip} has generated {top_count} alerts",
            'action': 'Consider blocking this IP if not whitelisted',
            'priority': 'high',
            'techniques': ['T1190']
        })
    
    # Add MITRE-specific recommendations
    if insights['mitre_techniques']:
        top_tech = max(insights['mitre_techniques'].items(), key=lambda x: x[1])
        tech_data = mitre_techniques.get(top_tech[0][0], {})
        
        insights['recommendations'].append({
            'title': 'Common ATT&CK Technique',
            'description': f"{top_tech[0][1]} detected {top_tech[1]} times",
            'action': f"Review defenses against {top_tech[0][0]}",
            'priority': 'medium',
            'techniques': [top_tech[0][0]],
            'mitre_data': tech_data
        })
    
    # Sort and limit results
    insights['common_techniques'] = dict(sorted(
        insights['stats']['by_type'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:5])
    
    insights['top_sources'] = dict(sorted(
        insights['top_sources'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:5])
    
    # Sort MITRE techniques
    insights['mitre_techniques'] = dict(sorted(
        insights['mitre_techniques'].items(),
        key=lambda x: x[1],
        reverse=True
    ))
    
    return insights
    
@app.route('/')
def index():
    try:
        if not os.path.exists(PCAP_DIR):
            logger.error(f"PCAP directory not found: {PCAP_DIR}")
            return render_template('error.html', message="PCAP directory not found"), 500

        grouped_files = {}
        ip_folders = [d for d in os.listdir(PCAP_DIR) if os.path.isdir(os.path.join(PCAP_DIR, d))]

        for ip_folder in ip_folders:
            ip_path = os.path.join(PCAP_DIR, ip_folder)
            try:
                pcap_files = [f for f in os.listdir(ip_path) if f.endswith(".pcap")]
                if pcap_files:
                    group_key = f"PC {ip_folder}"
                    grouped_files[group_key] = []
                    for file in pcap_files:
                        try:
                            file_path = os.path.join(ip_path, file)
                            timestamp = datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                            grouped_files[group_key].append((os.path.join(ip_folder, file), timestamp))
                        except Exception as e:
                            logger.error(f"Failed to process file {file}: {str(e)}")
                            continue
            except Exception as e:
                logger.error(f"Failed to process IP folder {ip_folder}: {str(e)}")
                continue

        return render_template('index.html', pcap_files=grouped_files)
    except Exception as e:
        logger.error(f"Unexpected error in index route: {str(e)}", exc_info=True)
        return render_template('error.html', message="Internal Server Error"), 500

@app.route('/pcap/<path:file_name>')
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
            file_name=os.path.basename(file_name),
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

@app.route('/mitre_attack')
def mitre_attack():
    try:
        # Load all available threats
        raw_threats = load_threats()
        pcap_threats = load_pcap_alerts()
        endpoint_alerts = load_endpoint_alerts()
        admin_threats = load_admin_log_alerts()
        network_threats = load_network_threats()
        
        all_threats = raw_threats + pcap_threats + endpoint_alerts + admin_threats + network_threats
        
        # Analyze threats for insights
        threat_insights = analyze_threats(all_threats)
        
        # Get MITRE techniques and ensure they're properly formatted
        mitre_techniques = fetch_mitre_techniques()
        
        # Ensure all techniques have the required structure
        formatted_mitre_techniques = {}
        for tech_id, tech_data in mitre_techniques.items():
            formatted_tech = {
                'name': tech_data.get('name', tech_id),
                'description': tech_data.get('description', 'No description available'),
                'tactics': tech_data.get('tactics', []),
                'url': tech_data.get('url', f'https://attack.mitre.org/techniques/{tech_id}/')
            }
            formatted_mitre_techniques[tech_id] = formatted_tech
        
        # Convert threat_insights.mitre_techniques to a serializable format
        if hasattr(threat_insights, 'mitre_techniques'):
            threat_insights['serialized_mitre_techniques'] = [
                {'tech_id': tech_id, 'tech_name': tech_name, 'count': count}
                for (tech_id, tech_name), count in threat_insights['mitre_techniques'].items()
            ]
        
        # Get all MITRE tactics for the matrix
        all_tactics = set()
        for tech in formatted_mitre_techniques.values():
            all_tactics.update(tech['tactics'])
        
        return render_template(
            'mitre_attack.html',
            threat_insights=threat_insights,
            mitre_techniques=formatted_mitre_techniques,
            all_tactics=all_tactics,
            total_threats=len(all_threats),
            last_updated=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
    except Exception as e:
        logger.error(f"Error in mitre_attack route: {str(e)}", exc_info=True)
        return render_template('error.html', message="Failed to load threat intelligence"), 500

        
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

        return jsonify({'reports': reports[:10]})
    except Exception as e:
        logger.error(f"Error listing reports: {str(e)}")
        return jsonify({'reports': []})

@app.route('/reports/<filename>')
def download_report(filename):
    reports_dir = '/home/robot/edr_server/reports'
    filepath = os.path.join(reports_dir, filename)

    if not os.path.exists(filepath):
        return "Report not found", 404

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

@app.route('/api/admin_monitoring')
def admin_monitoring_api():
    try:
        data = admin_monitor.get_current_data()
        
        # Add transformed threats and alerts
        admin_threats = load_admin_log_alerts()
        raw_network_threats = load_network_threats()
        
        network_threats = []
        for threat in raw_network_threats:
            transformed = {
                'source_ip': threat.get('source_ip', 'unknown'),
                'rule_name': threat.get('signature', 'Network Threat'),
                'type': threat.get('type', 'network'),
                'description': f"{threat.get('type', 'attack')} on {threat.get('service', 'service')}",
                'severity': threat.get('severity', 'medium'),
                'timestamp': threat.get('timestamp'),
                'category': threat.get('category', 'network'),
                'protocol': 'TCP',
                'attempts': threat.get('attempts'),
                'service': threat.get('service')
            }
            network_threats.append(transformed)
        
        data['threats'] = admin_threats
        data['alerts'] = network_threats
        
        return jsonify(data)
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
        
        # Load and transform network threats
        raw_network_threats = load_network_threats()
        network_threats = []
        
        for threat in raw_network_threats:
            transformed = {
                'source_ip': threat.get('source_ip', 'unknown'),
                'rule_name': threat.get('signature', 'Network Threat'),
                'description': f"{threat.get('type', 'attack')} on {threat.get('service', 'service')} - {threat.get('attempts', 0)} attempts",
                'severity': threat.get('severity', 'medium'),
                'timestamp': threat.get('timestamp'),
                'category': threat.get('category', 'network'),
                'protocol': 'TCP'  # Default protocol
            }
            network_threats.append(transformed)

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

        if os.path.exists(stats_file):
            try:
                with open(stats_file, 'r') as f:
                    cached_stats = json.load(f)

                    for section in ['network_stats', 'threat_stats', 'endpoint_stats']:
                        if section in cached_stats:
                            stats_data[section].update(cached_stats[section])

                    stats_data['log_stats'] = cached_stats.get('log_stats', [])

                    for viz in stats_data['visualizations']:
                        stats_data['visualizations'][viz] = cached_stats.get('visualizations', {}).get(viz, '')

            except Exception as e:
                logger.error(f"Error loading stats cache: {str(e)}")

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
                           if os.path.isfile(os.path.join(ip_path, f)) and
                           (f.endswith('.log') or f.endswith('.txt'))]
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
