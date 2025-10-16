import re

def simple_log_analyzer(log_file):
    """
    සරලම Log Analyzer - Failed login attempts සොයාගනී
    """
    print("🔍 Log Analyzer Starting...")
    
    # IP ලිපින සහ failed attempts count කිරීම
    ip_count = {}
    
    try:
        # Log file කියවීම
        with open(log_file, 'r') as file:
            for line in file:
                # "Failed password" ඇති lines සොයාගැනීම
                if "Failed password" in line:
                    # IP ලිපිනය extract කිරීම
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        
                        # IP count එක update කිරීම
                        if ip in ip_count:
                            ip_count[ip] += 1
                        else:
                            ip_count[ip] = 1
    except FileNotFoundError:
        print(f"❌ Error: '{log_file}' file not found!")
        return
    
    # Results display කිරීම
    print("\n📊 SECURITY REPORT")
    print("==================")
    
    if ip_count:
        # Failed attempts ගණන අනුව sort කිරීම
        sorted_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)
        
        for ip, count in sorted_ips:
            print(f"IP: {ip} - Failed attempts: {count}")
            
            # Threat level indication
            if count > 10:
                print("   🚨 CRITICAL - Possible brute force attack!")
            elif count > 5:
                print("   ⚠️  WARNING - Suspicious activity")
            elif count > 3:
                print("   ℹ️  NOTICE - Multiple failures")
                
    else:
        print("✅ No failed login attempts found")
    
    print(f"\n📈 Total unique IPs: {len(ip_count)}")
    print(f"📈 Total failed attempts: {sum(ip_count.values())}")

# කේතය run කිරීම
if __name__ == "__main__":
    # ඔබේ log file name එක මෙහි දමන්න
    log_file = "auth.log"  # Change this to your log file name
    
    simple_log_analyzer(log_file)
