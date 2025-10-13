import re
from collections import defaultdict

class SimpleLogAnalyzer:
    def __init__(self, threshold=3, report_file='security_report.txt'):
        self.failed_attempts = defaultdict(int)
        self.threshold = threshold
        self.report_file = report_file
    
    def parse_ssh_log(self, log_file):
        """Read and analyze SSH log file"""
        print("Starting SSH log analysis...")
        
        try:
            with open(log_file, 'r') as file:
                for line in file:
                    self._analyze_line(line)
        except FileNotFoundError:
            print(f"Log file not found: {log_file}")
            return
        
        self._generate_report()
    
    def _analyze_line(self, line):
        """Analyze a single log line"""
        failed_pattern = r'Failed password for (?:invalid user )?.* from (\d{1,3}(?:\.\d{1,3}){3})'
        match = re.search(failed_pattern, line)
        if match:
            ip_address = match.group(1)
            self.failed_attempts[ip_address] += 1
    
    def _generate_report(self):
        """Generate security report"""
        with open(self.report_file, 'w') as report:
            print("\n" + "="*50)
            print("Security Analysis Report")
            print("="*50)
            report.write("Security Analysis Report\n")
            report.write("="*50 + "\n")

            if not self.failed_attempts:
                print("No failed login attempts found")
                report.write("No failed login attempts found\n")
                return
            
            suspicious_ips = []
            for ip, count in self.failed_attempts.items():
                print(f"IP: {ip} - Failed attempts: {count}")
                report.write(f"IP: {ip} - Failed attempts: {count}\n")
                
                if count >= self.threshold:
                    suspicious_ips.append((ip, count))
            
            if suspicious_ips:
                print("\nSecurity Alerts!")
                print("Possible brute-force attacks from these IPs:")
                report.write("\nSecurity Alerts!\n")
                report.write("Possible brute-force attacks from these IPs:\n")
                for ip, count in suspicious_ips:
                    print(f"{ip} - {count} failed attempts")
                    report.write(f"{ip} - {count} failed attempts\n")

# Test template
def create_sample_log():
    sample_log = """
Jan 1 10:00:00 server sshd[1234]: Failed password for root from 192.168.1.100
Jan 1 10:00:01 server sshd[1235]: Failed password for root from 192.168.1.100
Jan 1 10:00:02 server sshd[1236]: Failed password for admin from 192.168.1.100
Jan 1 10:05:00 server sshd[1237]: Accepted password for user from 192.168.1.50
Jan 1 10:06:00 server sshd[1238]: Failed password for test from 10.0.0.5
    """
    with open('sample_ssh.log', 'w') as f:
        f.write(sample_log)
    return 'sample_ssh.log'

# Main execution
if __name__ == "__main__":
    log_file = create_sample_log()
    analyzer = SimpleLogAnalyzer(threshold=3)
    analyzer.parse_ssh_log(log_file)
    print(f"\nReport saved to: {analyzer.report_file}")
