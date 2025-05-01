import os
import json
import re
import yaml
import time
import logging
from datetime import datetime, timedelta
import subprocess
from src.utils import LOGS_DIR, logger  # Shared constants and logger

def load_rules():
    """Load rules from rules.yaml"""
    rules_path = '/home/robot/edr_server/rules.yaml'
    if not os.path.exists(rules_path):
        return []
    with open(rules_path, 'r') as f:
        return yaml.safe_load(f).get('rules', [])

def eval_condition(condition, log_fields):
    try:
        # Replace field names in the condition with their actual values
        for key, value in log_fields.items():
            # Wrap strings in quotes for eval safety
            if isinstance(value, str):
                value = f"'{value}'"
            condition = re.sub(rf'\b{key}\b', str(value), condition)
        return eval(condition)
    except Exception as e:
        logger.error(f"Error evaluating condition: {str(e)}")
        return False

def analyze_logs_with_clamav():
    """Scan logs with ClamAV and store results with enhanced logging."""
    clamav_results = []
    logger.info("Starting ClamAV scan of endpoint logs")

    for ip in os.listdir(LOGS_DIR):
        ip_path = os.path.join(LOGS_DIR, ip)
        if not os.path.isdir(ip_path):
            continue

        for log_file in os.listdir(ip_path):
            log_path = os.path.join(ip_path, log_file)
            if not os.path.isfile(log_path):
                continue

            try:
                result = subprocess.run(
                    ["clamscan", "--no-summary", log_path],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 1:  # Virus found
                    threat_info = {
                        'ip': ip,
                        'log_file': log_file,
                        'scan_output': result.stdout,
                        'timestamp': str(datetime.now())
                    }
                    clamav_results.append(threat_info)
                    logger.warning(f"Threat found in {log_path}")

            except Exception as e:
                logger.error(f"Failed to scan {log_path}: {str(e)}")

    # Save results
    results_file = '/home/robot/edr_server/clamav_results.json'
    with open(results_file, 'w') as f:
        json.dump(clamav_results, f, indent=4)

    return clamav_results

def periodic_clamav_scan():
    """Periodically scan logs with ClamAV with enhanced logging."""
    logger.info("Starting periodic ClamAV scans")
    while True:
        try:
            analyze_logs_with_clamav()
            logger.info("Completed ClamAV scan cycle")
        except Exception as e:
            logger.error(f"Error in periodic_clamav_scan: {str(e)}")
        time.sleep(300)

def parse_log_timestamp(line):
    """Parse timestamp from log lines"""
    try:
        return datetime.strptime(line[:15], '%b %d %H:%M:%S')
    except ValueError:
        return datetime.now()

def process_logs_threats():
    """Process log files for threat detection using rules"""
    threats = []
    rules = load_rules()
    logger.info(f"Starting log threat detection with {len(rules)} rules")

    # Debug: Log all loaded rules
    for i, rule in enumerate(rules, 1):
        logger.debug(f"Rule {i}: {rule['description']} (file: {rule['log_file']}, pattern: {rule['detection']['pattern']})")

    # Get list of endpoint IP directories
    try:
        endpoints = [d for d in os.listdir(LOGS_DIR) if os.path.isdir(os.path.join(LOGS_DIR, d))]
        logger.info(f"Found {len(endpoints)} endpoints: {endpoints}")
    except Exception as e:
        logger.error(f"Failed to list endpoints in {LOGS_DIR}: {str(e)}")
        return threats

    for endpoint_ip in endpoints:
        endpoint_path = os.path.join(LOGS_DIR, endpoint_ip)
        logger.info(f"Processing endpoint: {endpoint_ip}")

        # Get list of available log files for this endpoint
        try:
            endpoint_logs = os.listdir(endpoint_path)
            logger.debug(f"Found logs in {endpoint_ip}: {endpoint_logs}")
        except Exception as e:
            logger.error(f"Failed to list logs for {endpoint_ip}: {str(e)}")
            continue

        for rule in rules:
            # Try both original and filtered log names
            possible_log_files = [
                rule['log_file'],  # Original name from rules
                f"filtered_{rule['log_file']}",  # Prefixed with filtered_
                rule['log_file'].replace('.log', '')  # For cases like syslog vs filtered_syslog
            ]

            # Find the first matching log file that exists
            log_file = None
            for test_file in possible_log_files:
                test_path = os.path.join(endpoint_path, test_file)
                if os.path.exists(test_path):
                    log_file = test_file
                    break

            if not log_file:
                logger.debug(f"No matching log file found for rule {rule['description']} in {endpoint_ip}")
                continue

            full_log_path = os.path.join(endpoint_path, log_file)
            logger.info(f"Checking rule '{rule['description']}' against {log_file}")

            try:
                with open(full_log_path, 'r') as f:
                    lines = f.readlines()
                logger.debug(f"Read {len(lines)} lines from {log_file}")
            except Exception as e:
                logger.error(f"Failed to read {full_log_path}: {str(e)}")
                continue

            pattern = rule['detection']['pattern']
            threshold = rule['detection'].get('threshold', 1)
            time_window = rule['detection'].get('time_window', 'any')
            matched_lines = []

            for line_num, line in enumerate(lines, 1):
                try:
                    line = line.strip()
                    if not line:
                        continue

                    if re.search(pattern, line):
                        logger.debug(f"Match found in {log_file} line {line_num}: {line[:100]}...")
                        matched_lines.append({
                            'line': line,
                            'timestamp': parse_log_timestamp(line) if time_window != 'any' else datetime.now()
                        })
                except Exception as e:
                    logger.error(f"Error processing line {line_num} in {log_file}: {str(e)}")
                    continue

            # Apply time window filtering if needed
            if time_window != 'any':
                minutes = int(time_window.strip('mhs'))
                unit = time_window[-1]
                delta = {
                    'm': timedelta(minutes=minutes),
                    'h': timedelta(hours=minutes),
                    's': timedelta(seconds=minutes),
                }.get(unit, timedelta(minutes=5))

                now = datetime.now()
                matched_lines = [m for m in matched_lines if (now - m['timestamp']) <= delta]

            # Check if threshold is met
            if len(matched_lines) >= threshold:
                threat = {
                    "ip": endpoint_ip,
                    "log_file": log_file,
                    "message": rule['description'],
                    "detected_at": str(datetime.now()),
                    "count": len(matched_lines),
                    "sample_lines": [m['line'] for m in matched_lines[:3]]  # Include sample matches
                }
                threats.append(threat)
                logger.warning(f"THREAT DETECTED: {threat}")

    # Save results
    results_file = '/home/robot/edr_server/threats.json'
    try:
        with open(results_file, 'w') as f:
            json.dump(threats, f, indent=4)
        logger.info(f"Saved {len(threats)} threats to {results_file}")
    except Exception as e:
        logger.error(f"Failed to save threats: {str(e)}")

    return threats

def detect_threats():
    """Detect threats in log files using simple pattern matching"""
    rules = load_rules()
    threats = []

    for ip in os.listdir(LOGS_DIR):
        ip_path = os.path.join(LOGS_DIR, ip)
        if os.path.isdir(ip_path):
            for log_file in os.listdir(ip_path):
                log_path = os.path.join(ip_path, log_file)
                if os.path.isfile(log_path):
                    with open(log_path, 'r') as f:
                        log_data = f.readlines()
                    for rule in rules:
                        if 'detection' in rule and 'pattern' in rule['detection']:
                            pattern = rule['detection']['pattern']
                            for line in log_data:
                                if pattern in line:
                                    threats.append({
                                        'ip': ip,
                                        'log_file': log_file,
                                        'message': rule['description']
                                    })

    with open('/home/robot/edr_server/threats.json', 'w') as f:
        json.dump(threats, f, indent=4)

    return threats

def periodic_threat_detection():
    """Periodically detect threats in log files with better error handling"""
    logger.info("Starting periodic threat detection")
    while True:
        try:
            start_time = time.time()
            threats = process_logs_threats()

            # Save results
            results_file = '/home/robot/edr_server/threats.json'
            try:
                with open(results_file, 'w') as f:
                    json.dump(threats, f, indent=4)
                logger.info(f"Saved {len(threats)} threats to {results_file}")
            except Exception as e:
                logger.error(f"Failed to save threats: {str(e)}")

            elapsed = time.time() - start_time
            logger.info(f"Threat detection cycle completed in {elapsed:.2f} seconds")

        except Exception as e:
            logger.error(f"Error in periodic_threat_detection: {str(e)}")
            logger.error("Restarting threat detection after error...")

        time.sleep(300)

def analyze_logs_with_rules():
    """Analyze logs using the defined rules with enhanced pattern matching"""
    threats = []
    rules = load_rules()

    for endpoint_ip in os.listdir(LOGS_DIR):
        endpoint_path = os.path.join(LOGS_DIR, endpoint_ip)
        if not os.path.isdir(endpoint_path):
            continue

        for rule in rules:
            log_file = rule['log_file']
            detection = rule.get('detection', {})
            pattern = detection.get('pattern')
            threshold = detection.get('threshold', 1)
            time_window = detection.get('time_window', 'any')
            description = rule.get('description', 'No description provided.')

            full_log_path = os.path.join(endpoint_path, log_file)
            if not os.path.exists(full_log_path):
                continue

            with open(full_log_path, 'r') as f:
                lines = f.readlines()

            matches = []
            for line in lines:
                try:
                    if re.search(pattern, line, re.IGNORECASE):
                        timestamp = parse_log_timestamp(line)
                        matches.append({
                            'timestamp': timestamp,
                            'line': line.strip()
                        })
                except re.error as e:
                    logger.error(f"Regex error in rule '{description}': {str(e)}")
                    continue

            if time_window != 'any':
                # Convert time_window to timedelta
                time_value = int(time_window[:-1])
                time_unit = time_window[-1]

                if time_unit == 'm':
                    delta = timedelta(minutes=time_value)
                elif time_unit == 'h':
                    delta = timedelta(hours=time_value)
                elif time_unit == 's':
                    delta = timedelta(seconds=time_value)
                else:
                    delta = timedelta(minutes=5)  # default

                # Filter matches within the time window
                now = datetime.now()
                recent_matches = [m for m in matches if (now - m['timestamp']) <= delta]
            else:
                recent_matches = matches

            if len(recent_matches) >= threshold:
                threats.append({
                    'endpoint': endpoint_ip,
                    'log_file': log_file,
                    'rule_description': description,
                    'match_count': len(recent_matches),
                    'time_window': time_window,
                    'first_match': str(recent_matches[0]['timestamp']),
                    'last_match': str(recent_matches[-1]['timestamp']),
                    'sample_lines': [m['line'] for m in recent_matches[:3]],  # Include sample lines
                    'detected_at': str(datetime.now())
                })

    # Save results
    results_file = '/home/robot/edr_server/log_analysis_results.json'
    with open(results_file, 'w') as f:
        json.dump(threats, f, indent=4)

    logger.info(f"Log analysis completed. Found {len(threats)} potential threats.")
    return threats

def periodic_log_analysis():
    """Periodically analyze logs using the defined rules"""
    logger.info("Starting periodic log analysis")
    while True:
        try:
            analyze_logs_with_rules()
            logger.info("Completed log analysis cycle")
        except Exception as e:
            logger.error(f"Error in periodic_log_analysis: {str(e)}")
        time.sleep(300)

def process_logs_with_conditions():
    """Process logs using conditional evaluation from rules"""
    threats = []
    rules = load_rules()

    for endpoint_ip in os.listdir(LOGS_DIR):
        endpoint_path = os.path.join(LOGS_DIR, endpoint_ip)
        if not os.path.isdir(endpoint_path):
            continue

        for rule in rules:
            log_file = rule['log_file']
            condition = rule.get('condition', '')
            description = rule.get('description', 'No description provided.')

            full_log_path = os.path.join(endpoint_path, log_file)
            if not os.path.exists(full_log_path):
                continue

            # Parse log entries (assuming structured logs)
            entries = []
            with open(full_log_path, 'r') as f:
                for line in f:
                    try:
                        # Try to parse as JSON if logs are structured
                        entry = json.loads(line)
                        entries.append(entry)
                    except json.JSONDecodeError:
                        # Fall back to simple line processing
                        entries.append({'raw': line.strip()})

            for entry in entries:
                if eval_condition(condition, entry):
                    threats.append({
                        "endpoint": endpoint_ip,
                        "log_file": log_file,
                        "description": description,
                        "detected_at": str(datetime.now()),
                        "log_entry": entry
                    })
                    break  # Only report first match per rule per log file

    # Save results
    results_file = '/home/robot/edr_server/threats.json'
    with open(results_file, 'w') as f:
        json.dump(threats, f, indent=4)

    return threats
