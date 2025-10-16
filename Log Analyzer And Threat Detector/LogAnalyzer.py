import re

def simple_log_analyzer(log_file):
    print("Log Analyzer Starting...")
    
    ip_count = {}
    
    try:
        with open(log_file, 'r') as file:
            for line in file:
                if "Failed password" in line:
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        
                        if ip in ip_count:
                            ip_count[ip] += 1
                        else:
                            ip_count[ip] = 1
    except FileNotFoundError:
        print(f"Error: '{log_file}' file not found!")
        return
    
    # Results display කිරීම
    print("\nSECURITY REPORT")
    print("==================")
    
    if ip_count:
        sorted_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)
        
        for ip, count in sorted_ips:
            print(f"IP: {ip} - Failed attempts: {count}")
            
            if count > 10:
                print("   CRITICAL - Possible brute force attack!")
            elif count > 5:
                print("   WARNING - Suspicious activity")
            elif count > 3:
                print("   NOTICE - Multiple failures")
                
    else:
        print("No failed login attempts found")
    
    print(f"\n Total unique IPs: {len(ip_count)}")
    print(f" Total failed attempts: {sum(ip_count.values())}")

def create_sample_log():
    sample_content = """Jan 1 10:00:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 1 10:00:01 server sshd[1235]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 1 10:00:02 server sshd[1236]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 1 10:00:03 server sshd[1237]: Accepted password for user1 from 10.0.0.5 port 22 ssh2
Jan 1 10:00:04 server sshd[1238]: Failed password for test from 10.0.0.6 port 22 ssh2
Jan 1 10:00:05 server sshd[1239]: Failed password for guest from 10.0.0.6 port 22 ssh2
Jan 1 10:00:06 server sshd[1240]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 1 10:00:07 server sshd[1241]: Failed password for root from 203.0.113.45 port 22 ssh2
Jan 1 10:00:08 server sshd[1242]: Failed password for root from 203.0.113.45 port 22 ssh2
Jan 1 10:00:09 server sshd[1243]: Failed password for admin from 192.168.1.100 port 22 ssh2"""
    
    with open("auth.log", "w") as f:
        f.write(sample_content)
    
    print("Sample 'auth.log' file created!")
    print("Please run the analyzer again...")

if __name__ == "__main__":
    log_file = "auth.log" 
    
    simple_log_analyzer(log_file)
