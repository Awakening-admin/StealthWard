#!/usr/bin/env python3
import os
import json
import time
import psutil
import logging
from datetime import datetime, timedelta
from threading import Thread, Lock
import pdfkit
from jinja2 import Template
from collections import defaultdict

# Configuration
ADMIN_LOGS_DIR = "/home/robot/edr_server/admin_logs"
NETWORK_THREATS_FILE = "/home/robot/edr_server/network_threats.json"
ADMIN_LOG_ALERTS_FILE = "/home/robot/edr_server/ids_admin_log_alerts.json"
REPORTS_DIR = "/home/robot/edr_server/reports"
os.makedirs(ADMIN_LOGS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(ADMIN_LOGS_DIR, 'admin_monitor.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('AdminMonitor')

class SystemMonitor:
    def __init__(self):
        self.running = False
        self.current_interface = None
        self.last_analysis = None
        self.last_report_generation = 0
        self.last_traffic_stats = {
            'incoming_total': 0,
            'outgoing_total': 0,
            'timestamp': time.time()
        }
        self.last_threats_check = 0
        self.last_alerts_check = 0
        self.cached_threats = []
        self.cached_alerts = []
        self.data_lock = Lock()

    def get_network_traffic(self):
        try:
            interfaces = psutil.net_io_counters(pernic=True)
            if interfaces:
                active_iface = max(interfaces.keys(),
                                 key=lambda x: interfaces[x].bytes_sent + interfaces[x].bytes_recv)
                stats = interfaces[active_iface]
                current_time = time.time()

                time_diff = current_time - self.last_traffic_stats.get('timestamp', current_time)
                if time_diff > 0:
                    incoming_rate = (stats.bytes_recv - self.last_traffic_stats.get('incoming_total', 0)) / time_diff
                    outgoing_rate = (stats.bytes_sent - self.last_traffic_stats.get('outgoing_total', 0)) / time_diff
                else:
                    incoming_rate = outgoing_rate = 0

                self.last_traffic_stats = {
                    'incoming_total': stats.bytes_recv,
                    'outgoing_total': stats.bytes_sent,
                    'timestamp': current_time
                }
                self.current_interface = active_iface

                return {
                    'incoming_bps': incoming_rate,
                    'outgoing_bps': outgoing_rate,
                    'interface': active_iface,
                    'total_in': stats.bytes_recv,
                    'total_out': stats.bytes_sent
                }

            return {
                'incoming_bps': 0,
                'outgoing_bps': 0,
                'interface': 'unknown',
                'total_in': 0,
                'total_out': 0
            }
        except Exception as e:
            logger.error(f"Failed to get network stats: {e}")
            return {
                'incoming_bps': 0,
                'outgoing_bps': 0,
                'interface': 'error',
                'total_in': 0,
                'total_out': 0
            }

    def load_admin_alerts(self):
        current_time = time.time()
        if current_time - self.last_threats_check < 5 and self.cached_threats:
            return self.cached_threats

        alerts = []
        if os.path.exists(ADMIN_LOG_ALERTS_FILE):
            try:
                file_mtime = os.path.getmtime(ADMIN_LOG_ALERTS_FILE)
                if file_mtime > self.last_threats_check:
                    with open(ADMIN_LOG_ALERTS_FILE, 'r') as f:
                        alerts = json.load(f)
                        if not isinstance(alerts, list):
                            alerts = []
                        logger.info(f"Loaded {len(alerts)} admin log alerts")
                        for alert in alerts:
                            alert['type'] = 'admin_log'
                    self.cached_threats = alerts
                    self.last_threats_check = current_time
                else:
                    return self.cached_threats
            except Exception as e:
                logger.error(f"Error loading admin log alerts: {e}")
        return alerts

    def load_network_threats(self):
        current_time = time.time()
        if current_time - self.last_alerts_check < 5 and self.cached_alerts:
            return self.cached_alerts

        threats = []
        if os.path.exists(NETWORK_THREATS_FILE):
            try:
                file_mtime = os.path.getmtime(NETWORK_THREATS_FILE)
                if file_mtime > self.last_alerts_check:
                    with open(NETWORK_THREATS_FILE, 'r') as f:
                        threats = json.load(f)
                        if not isinstance(threats, list):
                            threats = []
                        logger.info(f"Loaded {len(threats)} network threats")
                        for threat in threats:
                            threat['rule_name'] = threat.get('signature', 'Network Alert')
                            threat['description'] = f"{threat.get('type', 'network')} activity"
                            threat['log_file'] = 'network'
                            # Ensure all required fields are present
                            threat['dest_ip'] = threat.get('dest_ip', 'unknown')
                            threat['dst_port'] = threat.get('dst_port', 'unknown')
                            threat['protocol'] = threat.get('protocol', 'unknown')
                    self.cached_alerts = threats
                    self.last_alerts_check = current_time
                else:
                    return self.cached_alerts
            except Exception as e:
                logger.error(f"Error loading network threats: {e}")
        return threats

    def generate_report(self):
            try:
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                report_data = {
                    'timestamp': current_time,
                    'network_stats': self.get_network_traffic(),
                    'threats': self.load_admin_alerts(),
                    'alerts': self.load_network_threats(),
                }
    
                # Process threats - group similar ones and calculate statistics
                threat_stats = {
                    'total': len(report_data['threats']),
                    'by_severity': defaultdict(int),
                    'by_source': defaultdict(int),
                    'by_type': defaultdict(int),
                    'critical_threats': []
                }
    
                for threat in report_data['threats']:
                    severity = threat.get('severity', 'medium').lower()
                    threat_stats['by_severity'][severity] += 1
                    
                    source = threat.get('source_ip', 'unknown')
                    threat_stats['by_source'][source] += 1
                    
                    threat_type = threat.get('rule_name', 'unknown')
                    threat_stats['by_type'][threat_type] += 1
                    
                    if severity in ['critical', 'high']:
                        threat_stats['critical_threats'].append(threat)
    
                # Process network alerts - group similar ones and calculate statistics
                alert_stats = {
                    'total': len(report_data['alerts']),
                    'by_severity': defaultdict(int),
                    'by_source': defaultdict(int),
                    'by_type': defaultdict(int),
                    'by_service': defaultdict(int),
                    'critical_alerts': [],
                    'total_attempts': 0
                }
    
                for alert in report_data['alerts']:
                    severity = alert.get('severity', 'medium').lower()
                    alert_stats['by_severity'][severity] += 1
                    
                    source = alert.get('source_ip', 'unknown')
                    alert_stats['by_source'][source] += 1
                    
                    alert_type = alert.get('signature', 'Network Alert')
                    alert_stats['by_type'][alert_type] += 1
                    
                    service = alert.get('service', 'unknown')
                    alert_stats['by_service'][service] += 1
                    
                    attempts = alert.get('attempts', 1)
                    alert_stats['total_attempts'] += attempts
                    
                    if severity in ['critical', 'high']:
                        alert_stats['critical_alerts'].append(alert)
    
                # Prepare report content with professional template
                template = Template("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Security Threat Report - {{ timestamp }}</title>
                    <style>
                        body { 
                            font-family: Arial, sans-serif; 
                            margin: 0; 
                            padding: 20px; 
                            color: #333;
                            line-height: 1.6;
                        }
                        .header { 
                            text-align: center; 
                            margin-bottom: 30px;
                            border-bottom: 2px solid #007bff;
                            padding-bottom: 20px;
                        }
                        .logo {
                            font-size: 24px;
                            font-weight: bold;
                            color: #007bff;
                            margin-bottom: 10px;
                        }
                        h1 { 
                            color: #dc3545; 
                            margin: 10px 0; 
                            font-size: 24px;
                        }
                        h2 {
                            color: #007bff;
                            font-size: 18px;
                            margin-top: 25px;
                            border-bottom: 1px solid #eee;
                            padding-bottom: 5px;
                        }
                        .section { 
                            margin-bottom: 30px;
                            page-break-inside: avoid;
                        }
                        .section-title { 
                            background: #f8f9fa; 
                            padding: 8px 15px; 
                            border-left: 4px solid #007bff;
                            font-weight: bold;
                            margin-bottom: 15px;
                        }
                        table { 
                            width: 100%; 
                            border-collapse: collapse; 
                            font-size: 12px; 
                            margin-top: 10px;
                            margin-bottom: 20px;
                        }
                        th, td { 
                            padding: 8px; 
                            text-align: left; 
                            border-bottom: 1px solid #ddd;
                            vertical-align: top;
                        }
                        th { 
                            background: #f8f9fa; 
                            font-weight: bold;
                        }
                        .severity { 
                            padding: 3px 6px; 
                            border-radius: 3px; 
                            font-weight: bold;
                            font-size: 11px;
                            white-space: nowrap;
                        }
                        .critical { background: #dc3545; color: white; }
                        .high { background: #fd7e14; color: white; }
                        .medium { background: #ffc107; }
                        .low { background: #6c757d; color: white; }
                        .footer { 
                            margin-top: 30px; 
                            text-align: center; 
                            color: #6c757d; 
                            font-size: 11px;
                            border-top: 1px solid #eee;
                            padding-top: 10px;
                        }
                        .stat-card {
                            background: #f8f9fa;
                            border-radius: 5px;
                            padding: 15px;
                            margin-bottom: 15px;
                            border-left: 4px solid #007bff;
                        }
                        .stat-value {
                            font-size: 24px;
                            font-weight: bold;
                            color: #007bff;
                        }
                        .stat-label {
                            font-size: 12px;
                            color: #6c757d;
                            text-transform: uppercase;
                        }
                        .alert-details {
                            background: #fff9f9;
                            padding: 10px;
                            border-radius: 5px;
                            margin: 10px 0;
                            border-left: 3px solid #ffcccc;
                        }
                        .threat-details {
                            background: #f9f9ff;
                            padding: 10px;
                            border-radius: 5px;
                            margin: 10px 0;
                            border-left: 3px solid #ccccff;
                        }
                        .details-title {
                            font-weight: bold;
                            margin-bottom: 5px;
                        }
                    </style>
                </head>
                <body>
                    <div class="header">
                        <div class="logo">StealthWard Endpoint Detection and Response</div>
                        <h1>Security Threat Report</h1>
                        <div>Generated: {{ timestamp }}</div>
                    </div>
    
                    <div class="section">
                        <div class="section-title">Executive Summary</div>
                        
                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 20px;">
                            <div class="stat-card">
                                <div class="stat-value">{{ threat_stats.total }}</div>
                                <div class="stat-label">Total System Threats</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">{{ alert_stats.total }}</div>
                                <div class="stat-label">Network Alerts</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">{{ alert_stats.total_attempts }}</div>
                                <div class="stat-label">Total Attack Attempts</div>
                            </div>
                        </div>
    
                        <p>This report covers security events detected on the admin system and network between 
                        {{ report_start_time }} and {{ timestamp }}. Key findings include:</p>
                        
                        <ul>
                            {% if threat_stats.critical_threats %}
                            <li><strong>{{ threat_stats.critical_threats|length }} critical threats</strong> detected on the admin system</li>
                            {% endif %}
                            {% if alert_stats.critical_alerts %}
                            <li><strong>{{ alert_stats.critical_alerts|length }} critical network alerts</strong> detected</li>
                            {% endif %}
                            {% if threat_stats.by_source %}
                            <li>Most active threat source: <strong>{{ threat_stats.by_source|dictsort(by='value')|reverse|first|first }}</strong> ({{ threat_stats.by_source|dictsort(by='value')|reverse|first|last }} events)</li>
                            {% endif %}
                            {% if alert_stats.by_source %}
                            <li>Most active network attacker: <strong>{{ alert_stats.by_source|dictsort(by='value')|reverse|first|first }}</strong> ({{ alert_stats.by_source|dictsort(by='value')|reverse|first|last }} alerts)</li>
                            {% endif %}
                        </ul>
                    </div>
    
                    <div class="section">
                        <div class="section-title">Network Status</div>
                        <table>
                            <tr>
                                <th>Interface</th>
                                <th>Incoming Traffic</th>
                                <th>Outgoing Traffic</th>
                                <th>Total In</th>
                                <th>Total Out</th>
                            </tr>
                            <tr>
                                <td>{{ network_stats.interface }}</td>
                                <td>{{ "%.2f"|format(network_stats.incoming_bps) }} B/s</td>
                                <td>{{ "%.2f"|format(network_stats.outgoing_bps) }} B/s</td>
                                <td>{{ "%.2f MB"|format(network_stats.total_in / (1024*1024)) }}</td>
                                <td>{{ "%.2f MB"|format(network_stats.total_out / (1024*1024)) }}</td>
                            </tr>
                        </table>
                    </div>
    
                    {% if threat_stats.total > 0 %}
                    <div class="section">
                        <div class="section-title">System Threat Analysis</div>
                        
                        <h2>Threat Overview</h2>
                        <table>
                            <tr>
                                <th>Severity</th>
                                <th>Count</th>
                                <th>Percentage</th>
                            </tr>
                            {% for severity, count in threat_stats.by_severity.items() %}
                            <tr>
                                <td><span class="{{ severity }}">{{ severity|upper }}</span></td>
                                <td>{{ count }}</td>
                                <td>{{ "%.1f"|format(count / threat_stats.total * 100) }}%</td>
                            </tr>
                            {% endfor %}
                        </table>
    
                        <h2>Top Threat Sources</h2>
                        <table>
                            <tr>
                                <th>Source IP</th>
                                <th>Count</th>
                            </tr>
                            {% for source, count in threat_stats.by_source|dictsort(by='value')|reverse|batch(5)|first %}
                            <tr>
                                <td>{{ source }}</td>
                                <td>{{ count }}</td>
                            </tr>
                            {% endfor %}
                        </table>
    
                        <h2>Critical Threat Details</h2>
                        {% for threat in threat_stats.critical_threats %}
                        <div class="threat-details">
                            <div class="details-title">{{ threat.rule_name }} <span class="{{ threat.severity }}">{{ threat.severity|upper }}</span></div>
                            <div><strong>Timestamp:</strong> {{ threat.timestamp }}</div>
                            {% if threat.source_ip %}<div><strong>Source IP:</strong> {{ threat.source_ip }}</div>{% endif %}
                            {% if threat.user %}<div><strong>User:</strong> {{ threat.user }}</div>{% endif %}
                            {% if threat.process %}<div><strong>Process:</strong> {{ threat.process }}</div>{% endif %}
                            <div><strong>Description:</strong> {{ threat.description or threat.log_line or 'No description available' }}</div>
                            {% if threat.log_file %}<div><strong>Log File:</strong> {{ threat.log_file }}</div>{% endif %}
                        </div>
                        {% endfor %}
                    </div>
                    {% endif %}
    
                    {% if alert_stats.total > 0 %}
                    <div class="section">
                        <div class="section-title">Network Threat Analysis</div>
                        
                        <h2>Alert Overview</h2>
                        <table>
                            <tr>
                                <th>Severity</th>
                                <th>Count</th>
                                <th>Percentage</th>
                            </tr>
                            {% for severity, count in alert_stats.by_severity.items() %}
                            <tr>
                                <td><span class="{{ severity }}">{{ severity|upper }}</span></td>
                                <td>{{ count }}</td>
                                <td>{{ "%.1f"|format(count / alert_stats.total * 100) }}%</td>
                            </tr>
                            {% endfor %}
                        </table>
    
                        <h2>Top Attack Sources</h2>
                        <table>
                            <tr>
                                <th>Source IP</th>
                                <th>Alerts</th>
                                <th>Attempts</th>
                            </tr>
                            {% for source in alert_stats.by_source|dictsort(by='value')|reverse|batch(5)|first %}
                            <tr>
                                <td>{{ source[0] }}</td>
                                <td>{{ source[1] }}</td>
                                <td>
                                    {% set attempts = alert_stats.total_attempts if alert_stats.by_source|length == 1 else 
                                        (alert_stats.total_attempts * source[1] / alert_stats.total)|round %}
                                    {{ attempts }}
                                </td>
                            </tr>
                            {% endfor %}
                        </table>
    
                        <h2>Targeted Services</h2>
                        <table>
                            <tr>
                                <th>Service</th>
                                <th>Alerts</th>
                            </tr>
                            {% for service, count in alert_stats.by_service|dictsort(by='value')|reverse|batch(5)|first %}
                            <tr>
                                <td>{{ service }}</td>
                                <td>{{ count }}</td>
                            </tr>
                            {% endfor %}
                        </table>
    
                        <h2>Critical Alert Details</h2>
                        {% for alert in alert_stats.critical_alerts %}
                        <div class="alert-details">
                            <div class="details-title">{{ alert.signature or alert.rule_name }} <span class="{{ alert.severity }}">{{ alert.severity|upper }}</span></div>
                            <div><strong>Timestamp:</strong> {{ alert.timestamp }}</div>
                            <div><strong>Source IP:</strong> {{ alert.source_ip }}</div>
                            {% if alert.dest_ip %}<div><strong>Target IP:</strong> {{ alert.dest_ip }}</div>{% endif %}
                            {% if alert.service %}<div><strong>Service:</strong> {{ alert.service }}</div>{% endif %}
                            {% if alert.attempts %}<div><strong>Attempts:</strong> {{ alert.attempts }}</div>{% endif %}
                            {% if alert.protocol %}<div><strong>Protocol:</strong> {{ alert.protocol }}</div>{% endif %}
                            {% if alert.category %}<div><strong>Category:</strong> {{ alert.category }}</div>{% endif %}
                        </div>
                        {% endfor %}
                    </div>
                    {% endif %}
    
                    <div class="section">
                        <div class="section-title">Recommendations</div>
                        
                        {% if threat_stats.critical_threats or alert_stats.critical_alerts %}
                        <h2>Immediate Actions</h2>
                        <ul>
                            {% if alert_stats.by_source %}
                            <li><strong>Block malicious IPs:</strong> Consider blocking the top attacking IPs ({{ alert_stats.by_source|dictsort(by='value')|reverse|first|first }}) at the firewall level</li>
                            {% endif %}
                            {% if alert_stats.by_service %}
                            <li><strong>Harden vulnerable services:</strong> The most targeted service was {{ alert_stats.by_service|dictsort(by='value')|reverse|first|first }} - review its configuration and access controls</li>
                            {% endif %}
                            <li><strong>Review authentication logs:</strong> Check for any successful unauthorized access attempts</li>
                        </ul>
                        {% endif %}
    
                        <h2>Long-term Improvements</h2>
                        <ul>
                            <li><strong>Implement rate limiting:</strong> For services like SSH to prevent brute force attacks</li>
                            <li><strong>Update and patch:</strong> Ensure all systems and services are up-to-date with security patches</li>
                            <li><strong>Review monitoring rules:</strong> Fine-tune alert thresholds to reduce false positives</li>
                        </ul>
                    </div>
    
                    <div class="footer">
                        <p>Automated Security Report | StealthWard Endpoint Detection and Response | © {{ timestamp[-4:] }}</p>
                    </div>
                </body>
                </html>
                """)
    
                # Calculate report start time (24 hours before current time)
                report_start_time = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
    
                html_content = template.render(
                    timestamp=report_data['timestamp'],
                    report_start_time=report_start_time,
                    network_stats=report_data['network_stats'],
                    threat_stats=threat_stats,
                    alert_stats=alert_stats
                )
    
                # Generate PDF
                report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                report_path = os.path.join(REPORTS_DIR, report_filename)
    
                pdfkit.from_string(html_content, report_path, options={
                    'encoding': 'UTF-8',
                    'quiet': '',
                    'page-size': 'A4',
                    'margin-top': '10mm',
                    'margin-right': '10mm',
                    'margin-bottom': '10mm',
                    'margin-left': '10mm',
                    'dpi': '300',
                    'footer-center': 'Page [page] of [toPage]'
                })
    
                self.last_report_generation = time.time()
                logger.info(f"Generated comprehensive security report: {report_path}")
                return report_path
            except Exception as e:
                logger.error(f"Failed to generate report: {e}")
                return None
    

    def _get_severity_level(self, severity):
        severity_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        return severity_map.get(severity.lower() if severity else 'low', 1)

    def get_current_data(self):
        self.last_analysis = datetime.now().isoformat()
        return {
            'network_stats': self.get_network_traffic(),
            'alerts': self.load_network_threats(),
            'threats': self.load_admin_alerts(),
            'status': {
                'is_running': self.running,
                'last_analysis': self.last_analysis
            }
        }

    def run(self):
        self.running = True
        try:
            while self.running:
                self.get_network_traffic()

                # Generate report every 5 minutes
                current_time = time.time()
                if current_time - self.last_report_generation > 300:  # 5 minutes
                    self.generate_report()
                    self.last_report_generation = current_time

                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received shutdown signal")
        except Exception as e:
            logger.error(f"Unexpected error in main loop: {e}")
        finally:
            self.running = False

def run_admin_monitor():
    monitor = SystemMonitor()
    monitor_thread = Thread(target=monitor.run, daemon=True)
    monitor_thread.start()
    return monitor

if __name__ == '__main__':
    monitor = SystemMonitor()
    monitor.run()
