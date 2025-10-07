import re
from collections import defaultdict

class SimpleLogAnalyzer:
    def __init__(self):
        self.failed_attempts = defaultdict(int)
    
    def parse_ssh_log(self, log_file):
        """Read and analyze SSH log file"""
        print("🔍 Starting SSH log analysis...")
        
        try:
            with open(log_file, 'r') as file:
                for line in file:
                    self._analyze_line(line)
        except FileNotFoundError:
            print(f"❌ Log file not found: {log_file}")
            return
        
        self._generate_report()
    
    def _analyze_line(self, line):
        """Analyze a single log line"""
        # Failed password pattern
        failed_pattern = r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)'
        match = re.search(failed_pattern, line)
        
        if match:
            ip_address = match.group(1)
            self.failed_attempts[ip_address] += 1
    
    def _generate_report(self):
        """Generate security report"""
        print("\n" + "="*50)
        print("📊 Security Analysis Report")
        print("="*50)
        
        if not self.failed_attempts:
            print("✅ No failed login attempts found")
            return
        
        suspicious_ips = []
        
        for ip, count in self.failed_attempts.items():
            print(f"IP: {ip} - Failed attempts: {count}")
            
            # Add to suspicious IP list
            if count >= 3:
                suspicious_ips.append((ip, count))
        
        # Alert for suspicious IPs
        if suspicious_ips:
            print("\n🚨 Security Alerts!")
            print("Possible brute-force attacks from these IPs:")
            for ip, count in suspicious_ips:
                print(f"⚠️  {ip} - {count} failed attempts")

# Test template
def create_sample_log():
    """Create sample log file for testing"""
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
    # Create sample log file
    log_file = create_sample_log()
    
    # Analyze the log
    analyzer = SimpleLogAnalyzer()
    analyzer.parse_ssh_log(log_file)