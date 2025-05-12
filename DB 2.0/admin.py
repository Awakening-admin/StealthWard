#!/usr/bin/env python3
import os
import json
import time
import psutil
import logging
from datetime import datetime
from threading import Thread, Lock
import pdfkit
from jinja2 import Template

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

            # Process threats - group by type, get most critical
            threat_summary = {}
            for threat in report_data['threats']:
                key = (threat.get('rule_name'), threat.get('source_ip'))
                if key not in threat_summary:
                    threat_summary[key] = {
                        'count': 0,
                        'max_severity': 'low',
                        'example': threat
                    }
                threat_summary[key]['count'] += 1
                if self._get_severity_level(threat.get('severity')) > self._get_severity_level(threat_summary[key]['max_severity']):
                    threat_summary[key]['max_severity'] = threat.get('severity', 'low')

            # Process alerts - group by signature and IP pair
            alert_summary = {}
            for alert in report_data['alerts']:
                key = (
                    alert.get('signature'), 
                    alert.get('source_ip', 'Unknown'), 
                    alert.get('dest_ip', 'Unknown')
                )
                if key not in alert_summary:
                    alert_summary[key] = {
                        'count': 0,
                        'max_severity': 'low',
                        'example': alert
                    }
                alert_summary[key]['count'] += 1
                if self._get_severity_level(alert.get('severity')) > self._get_severity_level(alert_summary[key]['max_severity']):
                    alert_summary[key]['max_severity'] = alert.get('severity', 'low')

            # Prepare report content
            template = Template("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Security Report - {{ timestamp }}</title>
                <style>
                    body { font-family: Arial; margin: 0; padding: 10px; font-size: 10px; }
                    .header { text-align: center; margin-bottom: 10px; }
                    h1 { color: #dc3545; margin: 5px 0; font-size: 14px; }
                    .section { margin-bottom: 10px; }
                    .section-title { background: #f8f9fa; padding: 3px 5px; border-left: 3px solid #007bff; }
                    table { width: 100%; border-collapse: collapse; font-size: 9px; margin-top: 5px; }
                    th, td { padding: 3px; text-align: left; border-bottom: 1px solid #ddd; }
                    th { background: #f8f9fa; }
                    .severity { padding: 1px 3px; border-radius: 3px; font-weight: bold; }
                    .critical { background: #dc3545; color: white; }
                    .high { background: #fd7e14; color: white; }
                    .medium { background: #ffc107; }
                    .low { background: #6c757d; color: white; }
                    .footer { margin-top: 10px; text-align: center; color: #6c757d; font-size: 8px; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Security Threat Report</h1>
                    <div>Generated: {{ timestamp }}</div>
                </div>

                <div class="section">
                    <div class="section-title">Network Status</div>
                    <table>
                        <tr>
                            <th>Interface</th>
                            <th>Incoming</th>
                            <th>Outgoing</th>
                        </tr>
                        <tr>
                            <td>{{ network_stats.interface }}</td>
                            <td>{{ "%.2f"|format(network_stats.incoming_bps) }} B/s</td>
                            <td>{{ "%.2f"|format(network_stats.outgoing_bps) }} B/s</td>
                        </tr>
                    </table>
                </div>

                {% if threat_summary %}
                <div class="section">
                    <div class="section-title">System Threats ({{ threat_summary|length }} unique)</div>
                    <table>
                        <tr>
                            <th>Threat</th>
                            <th>Source IP</th>
                            <th>Count</th>
                            <th>Severity</th>
                        </tr>
                        {% for key, data in threat_summary.items() %}
                        <tr>
                            <td>{{ key[0] or 'Unknown' }}</td>
                            <td>{{ key[1] or 'Unknown' }}</td>
                            <td>{{ data.count }}</td>
                            <td><span class="{{ data.max_severity }}">{{ data.max_severity|upper }}</span></td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>
                {% endif %}

                {% if alert_summary %}
                <div class="section">
                    <div class="section-title">Network Alerts ({{ alert_summary|length }} unique)</div>
                    <table>
                        <tr>
                            <th>Alert</th>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Count</th>
                            <th>Severity</th>
                        </tr>
                        {% for key, data in alert_summary.items() %}
                        <tr>
                            <td>{{ key[0] or 'Network Alert' }}</td>
                            <td>{{ key[1] }}</td>
                            <td>{{ key[2] }}</td>
                            <td>{{ data.count }}</td>
                            <td><span class="{{ data.max_severity }}">{{ data.max_severity|upper }}</span></td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>
                {% endif %}

                <div class="footer">
                    <p>Automated Security Report | © {{ timestamp[-4:] }}</p>
                </div>
            </body>
            </html>
            """)

            html_content = template.render(
                timestamp=report_data['timestamp'],
                network_stats=report_data['network_stats'],
                threat_summary=dict(sorted(threat_summary.items(), 
                    key=lambda x: (-x[1]['count'], x[1]['max_severity']))),
                alert_summary=dict(sorted(alert_summary.items(), 
                    key=lambda x: (-x[1]['count'], x[1]['max_severity']))),
            )

            # Generate PDF
            report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            report_path = os.path.join(REPORTS_DIR, report_filename)
            
            pdfkit.from_string(html_content, report_path, options={
                'encoding': 'UTF-8',
                'quiet': '',
                'page-size': 'A4',
                'margin-top': '5mm',
                'margin-right': '5mm',
                'margin-bottom': '5mm',
                'margin-left': '5mm',
                'dpi': '96'
            })

            self.last_report_generation = time.time()
            logger.info(f"Generated concise security report: {report_path}")
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