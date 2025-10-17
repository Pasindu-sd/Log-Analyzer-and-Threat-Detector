from src.analyzer import read_log_file, failed_logins
from src.detector import detect_threats

if __name__ == "__main__":
    log_file = "logs/auth.log"

    print("Log Analyzer Starting...\n")
    lines = read_log_file(log_file)
    failed_ips = failed_logins(lines)

    if failed_ips:
        threats = detect_threats(failed_ips)
        print("=== SECURITY REPORT ===")
        for ip, count, level in threats:
            print(f"IP: {ip} - Failed attempts: {count} | {level}")

        print(f"\nTotal unique IPs: {len(set(failed_ips))}")
        print(f"Total failed attempts: {len(failed_ips)}")
    else:
        print("No failed login attempts found.")
