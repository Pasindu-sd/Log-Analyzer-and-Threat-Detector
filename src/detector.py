from collections import Counter

def detect_threats(ip_list):
    ip_count = Counter(ip_list)
    alerts = []

    for ip, count in ip_count.items():
        if count > 10:
            alerts.append((ip, count, "CRITICAL - Possible brute force attack"))
        elif count > 5:
            alerts.append((ip, count, "WARNING - Suspicious activity"))
        elif count > 3:
            alerts.append((ip, count, "NOTICE - Multiple failed attempts"))

    return alerts
