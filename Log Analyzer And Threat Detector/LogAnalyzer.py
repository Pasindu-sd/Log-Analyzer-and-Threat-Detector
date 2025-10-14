import re
from collections import defaultdict

def analyze_ssh_log(log_file, report_file, threshold=3):
    failed_attempts = defaultdict(int)

    # Read log file
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                failed_attempts[ip] += 1

    # Sort IPs by number of failed attempts (descending)
    sorted_attempts = sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True)

    # Generate report
    with open(report_file, 'w') as report:
        print("\n=== Security Report ===")
        report.write("=== Security Report ===\n")

        if not sorted_attempts:
            print("No failed login attempts found")
            report.write("No failed login attempts found\n")
        else:
            for ip, count in sorted_attempts:
                print(f"IP: {ip} - Failed attempts: {count}")
                report.write(f"IP: {ip} - Failed attempts: {count}\n")

            print("\n🚨 Suspicious IPs (Over Threshold):")
            report.write("\nSuspicious IPs:\n")
            for ip, count in sorted_attempts:
                if count >= threshold:
                    print(f"⚠️ {ip} - {count} failed attempts")
                    report.write(f"{ip} - {count} failed attempts\n")

    print(f"\n📄 Report saved to: {report_file}")

# Run function
analyze_ssh_log('sample_ssh.log', 'security_report.txt', threshold=3)
