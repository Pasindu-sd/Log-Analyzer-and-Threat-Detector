import re
from collections import defaultdict

def log_analyzer(log_file, report_file):
    print("log analyzer Starting...")
    
    failed_logins = defaultdict(int)
    successful_logins = []
    error_messages = []
    
    
    