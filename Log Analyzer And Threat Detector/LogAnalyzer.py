import re
from collections import defaultdict

def log_analyzer(log_file, report_file):
    print("log analyzer Starting...")
    
    failed_logins = defaultdict(int)
    successful_logins = []
    error_messages = []
    
    attack_patterns = {
        'brute_force': r'Failed password|Authentication failed',
        'suspicious_user': r'root|admin|test|guest',
        'port_scan': r'Connection closed|Did not receive identification',
        'malicious_ips': r'from (192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)'
    }
    
