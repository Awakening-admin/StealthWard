import os
import re
import json
import yaml
from datetime import datetime

class AdminLogAnalyzer:
    def __init__(self):
        self.log_dir = "/var/log"
        self.rules_file = "/home/robot/edr_server/admin_rules.yaml"
        self.output_file = "/home/robot/edr_server/ids_admin_log_alerts.json"
        self.rules = self.load_rules()
        self.seen_alerts = set()  # Track seen alerts to prevent duplicates

    def load_rules(self):
        """Load rules from YAML file with proper structure"""
        try:
            with open(self.rules_file, 'r') as f:
                rules_data = yaml.safe_load(f) or {}
                simple_rules = {}
                for rule in rules_data.get('rules', []):
                    if 'detection' in rule and 'pattern' in rule['detection']:
                        rule_name = rule.get('description', "unnamed_rule")
                        simple_rules[rule_name] = {
                            'pattern': rule['detection']['pattern'],
                            'description': rule.get('description', ''),
                            'severity': rule.get('severity', 'medium')
                        }
                return simple_rules
        except Exception as e:
            print(f"[!] Error loading rules: {e}")
            return {}

    def analyze_logs(self):
        """Analyze all log files and save only new alerts"""
        if not os.path.exists(self.log_dir):
            print(f"[!] Log directory not found: {self.log_dir}")
            return

        # Load existing alerts to prevent duplicates
        self.load_existing_alerts()

        new_alerts = []
        log_files = ['auth.log', 'syslog', 'messages', 'secure']

        for log_file in log_files:
            filepath = os.path.join(self.log_dir, log_file)
            if os.path.exists(filepath):
                new_alerts.extend(self.analyze_log_file(filepath))

        if new_alerts:
            self.save_alerts(new_alerts)
            print(f"[+] Found {len(new_alerts)} new admin log alerts")
        else:
            print("[*] No new admin log alerts detected")

    def load_existing_alerts(self):
        """Load existing alerts to track what we've already seen"""
        if os.path.exists(self.output_file):
            try:
                with open(self.output_file, 'r') as f:
                    for alert in json.load(f):
                        self.seen_alerts.add(self._alert_signature(alert))
            except Exception as e:
                print(f"[!] Error loading existing alerts: {e}")

    def _alert_signature(self, alert):
        """Create unique signature for an alert to detect duplicates"""
        return f"{alert['log_file']}:{alert['log_line']}:{alert['rule_name']}"

    def analyze_log_file(self, filepath):
        """Analyze a single log file and return only new alerts"""
        alerts = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    for rule_name, rule in self.rules.items():
                        try:
                            if re.search(rule['pattern'], line, re.IGNORECASE):
                                alert = {
                                    'timestamp': datetime.now().isoformat(),
                                    'log_file': os.path.basename(filepath),
                                    'log_line': line,
                                    'rule_name': rule_name,
                                    'description': rule.get('description', ''),
                                    'severity': rule.get('severity', 'medium')
                                }
                                sig = self._alert_signature(alert)
                                if sig not in self.seen_alerts:
                                    alerts.append(alert)
                                    self.seen_alerts.add(sig)
                        except re.error:
                            continue
        except Exception as e:
            print(f"[!] Error reading {filepath}: {e}")
        return alerts

    def save_alerts(self, alerts):
        """Append new alerts to output file"""
        try:
            # Read existing alerts
            existing_alerts = []
            if os.path.exists(self.output_file):
                with open(self.output_file, 'r') as f:
                    existing_alerts = json.load(f)

            # Append new alerts
            existing_alerts.extend(alerts)

            # Save back to file
            with open(self.output_file, 'w') as f:
                json.dump(existing_alerts, f, indent=2)

        except Exception as e:
            print(f"[!] Failed to save alerts: {e}")
