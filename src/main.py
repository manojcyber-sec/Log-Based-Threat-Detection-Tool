# SOC Threat Detection Tool
# main.py - Main Entry Point

import sys
import os

sys.path.append(os.path.dirname(__file__))

from detector import run_all_detections
from reporter import generate_report, save_report

def main():
    log_file = "../logs/windows_security.log"
    report_file = "../reports/alert_report.txt"
    
    print("\nSOC Threat Detection Tool Starting...")
    print(f"Analyzing: {log_file}")
    
    alerts = run_all_detections(log_file)
    
    generate_report(alerts)
    
    save_report(alerts, report_file)

main()
