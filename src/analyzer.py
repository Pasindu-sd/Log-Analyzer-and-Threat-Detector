import re

def read_log_file(file_path):
    try:
        with open(file_path, 'r') as f:
            return f.readlines()
    except FileNotFoundError:
        print(f"Log file '{file_path}' not found!")
        return []

def failed_logins(log_lines):
    failed_ips = []
    for line in log_lines:
        if "Failed password" in line:
            match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                failed_ips.append(match.group(1))
    return failed_ips
