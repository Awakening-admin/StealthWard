import os
import re
import json
from datetime import datetime

class EndpointLogAnalyzer:
    def __init__(self):
        self.log_dir = "/home/robot/edr_server/Logs"
        self.output_file = "/home/robot/edr_server/threats.json"
        self.rules = self.load_rules()

    def load_rules(self):
        return {
            'ssh_failure': {
                'pattern': r'Failed password|authentication failure',
                'description': 'SSH login failure',
                'severity': 'medium'
            },
            'sudo_attempt': {
                'pattern': r'sudo:.*user NOT in sudoers',
                'description': 'Unauthorized sudo attempt',
                'severity': 'high'
            },
            'http_attack': {
                'pattern': r'HTTP attack|SQL injection|XSS',
                'description': 'Web attack detected',
                'severity': 'high'
            }
        }

    def analyze_logs(self):
        if not os.path.exists(self.log_dir):
            return

        alerts = []

        # Process each endpoint directory (IP-named folders)
        for endpoint_ip in os.listdir(self.log_dir):
            endpoint_path = os.path.join(self.log_dir, endpoint_ip)
            if os.path.isdir(endpoint_path):
                for log_file in os.listdir(endpoint_path):
                    filepath = os.path.join(endpoint_path, log_file)
                    alerts.extend(self.analyze_log_file(filepath, endpoint_ip))

        if alerts:
            with open(self.output_file, 'w') as f:
                json.dump(alerts, f, indent=2)

    def analyze_log_file(self, filepath, endpoint_ip):
        alerts = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    for rule_name, rule in self.rules.items():
                        if re.search(rule['pattern'], line, re.IGNORECASE):
                            alerts.append({
                                'timestamp': datetime.now().isoformat(),
                                'endpoint_ip': endpoint_ip,
                                'log_file': os.path.basename(filepath),
                                'log_line': line.strip(),
                                'rule_name': rule_name,
                                'description': rule['description'],
                                'severity': rule['severity']
                            })
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
        return alerts
