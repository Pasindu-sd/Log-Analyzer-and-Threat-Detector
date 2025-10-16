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

if __name__ == "__main__":
    log_file = "auth.log" 
    
    simple_log_analyzer(log_file)
