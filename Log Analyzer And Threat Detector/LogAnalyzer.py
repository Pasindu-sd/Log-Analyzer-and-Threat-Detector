import re
from collections import defaultdict

failed_attempts = defaultdict(int)
threshold = 3  # alert level
report_file = 'security_report.txt'

# Read log file
with open('sample_ssh.log', 'r') as file:
    for line in file:
        match = re.search(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip = match.group(1)
            failed_attempts[ip] += 1

# Generate report
with open(report_file, 'w') as report:
    print("\n=== Security Report ===")
    report.write("=== Security Report ===\n")

    if not failed_attempts:
        print("No failed login attempts found")
        report.write("No failed login attempts found\n")
    else:
        for ip, count in failed_attempts.items():
            print(f"IP: {ip} - Failed attempts: {count}")
            report.write(f"IP: {ip} - Failed attempts: {count}\n")

        print("\nSuspicious IPs:")
        report.write("\nSuspicious IPs:\n")
        for ip, count in failed_attempts.items():
            if count >= threshold:
                print(f"{ip} - {count} failed attempts")
                report.write(f"{ip} - {count} failed attempts\n")

print(f"\n Report saved to: {report_file}")

