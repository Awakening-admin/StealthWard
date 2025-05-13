import os
import re
import json
import yaml
from datetime import datetime
from collections import defaultdict

class EndpointLogAnalyzer:
    def __init__(self):
        self.log_dir = "/home/robot/edr_server/Logs"
        self.rules_file = "/home/robot/edr_server/rules.yaml"
        self.output_file = "/home/robot/edr_server/threats.json"
        self.rules = self.load_rules()
        self.seen_threats = defaultdict(int)  # To track repeated threats

    def load_rules(self):
        """Load detection rules from YAML file"""
        try:
            with open(self.rules_file, 'r') as f:
                rules_data = yaml.safe_load(f)

            # Convert YAML rules to our internal format
            processed_rules = {}
            for rule in rules_data.get('rules', []):
                rule_name = rule['description'].lower().replace(' ', '_')
                processed_rules[rule_name] = {
                    'log_file': rule.get('log_file', ''),
                    'pattern': rule['detection'].get('pattern', ''),
                    'description': rule['description'],
                    'severity': rule['severity'],
                    'threshold': rule['detection'].get('threshold', 1),
                    'time_window': rule['detection'].get('time_window', '0m')
                }
            return processed_rules
        except Exception as e:
            print(f"Error loading rules from YAML: {e}")
            # Fallback to default rules if YAML loading fails
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
                }
            }

    def analyze_logs(self):
        """Analyze all endpoint logs in the Logs directory"""
        if not os.path.exists(self.log_dir):
            print(f"Log directory not found: {self.log_dir}")
            return

        alerts = []

        # Process each endpoint directory (IP-named folders)
        for endpoint_ip in os.listdir(self.log_dir):
            endpoint_path = os.path.join(self.log_dir, endpoint_ip)
            if os.path.isdir(endpoint_path):
                for log_file in os.listdir(endpoint_path):
                    filepath = os.path.join(endpoint_path, log_file)
                    alerts.extend(self.analyze_log_file(filepath, endpoint_ip))

        # Process alerts to consolidate duplicates
        processed_alerts = self.process_duplicate_alerts(alerts)

        if processed_alerts:
            with open(self.output_file, 'w') as f:
                json.dump(processed_alerts, f, indent=2)

    def analyze_log_file(self, filepath, endpoint_ip):
        """Analyze a single log file for threats"""
        alerts = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    for rule_name, rule in self.rules.items():
                        # Skip if this rule doesn't apply to this log file
                        if rule['log_file'] and not filepath.endswith(rule['log_file']):
                            continue

                        if re.search(rule['pattern'], line, re.IGNORECASE):
                            # Create a unique key for this threat type from this source
                            threat_key = f"{endpoint_ip}-{rule_name}-{line.strip()[:100]}"
                            self.seen_threats[threat_key] += 1

                            alerts.append({
                                'timestamp': datetime.now().isoformat(),
                                'endpoint_ip': endpoint_ip,
                                'log_file': os.path.basename(filepath),
                                'log_line': line.strip(),
                                'rule_name': rule_name,
                                'description': rule['description'],
                                'severity': rule['severity'],
                                'count': self.seen_threats[threat_key],
                                'is_duplicate': False  # Will be processed later
                            })
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
        return alerts

    def process_duplicate_alerts(self, alerts):
        """Consolidate duplicate alerts and mark them appropriately"""
        # Group alerts by threat type and source
        alert_groups = defaultdict(list)
        for alert in alerts:
            key = (alert['endpoint_ip'], alert['rule_name'], alert['log_file'])
            alert_groups[key].append(alert)

        processed_alerts = []
        for group in alert_groups.values():
            if len(group) == 1:
                processed_alerts.append(group[0])
            else:
                # Sort by count descending and take the most recent with highest count
                group.sort(key=lambda x: (-x['count'], x['timestamp']))
                main_alert = group[0]
                main_alert['count'] = len(group)
                processed_alerts.append(main_alert)

                # Mark the rest as duplicates
                for dup_alert in group[1:]:
                    dup_alert['is_duplicate'] = True
                    processed_alerts.append(dup_alert)

        return processed_alerts
