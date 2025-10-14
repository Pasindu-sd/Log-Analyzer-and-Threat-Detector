import re

threshold = 3
counts = {}

with open('sample_ssh.log') as f:
    for line in f:
        m = re.search(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)', line)
        if m:
            ip = m.group(1)
            counts[ip] = counts.get(ip, 0) + 1

with open('security_report.txt', 'w') as rpt:
    rpt.write("=== Security Report ===\n")
    if not counts:
        rpt.write("No failed login attempts found\n")
        print("No failed login attempts found")
    else:
        for ip, c in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            line = f"IP: {ip} - Failed attempts: {c}\n"
            rpt.write(line)
            print(line, end='')

        rpt.write("\nSuspicious IPs (>= %d):\n" % threshold)
        print("\nSuspicious IPs (>= %d):" % threshold)
        for ip, c in counts.items():
            if c >= threshold:
                rpt.write(f"{ip} - {c} failed attempts\n")
                print(f"{ip} - {c} failed attempts")

print("\nReport saved to: security_report.txt")
