from datetime import datetime


def get_action(alert_type):
    if alert_type == "Brute Force":
        return "Block IP or enable MFA"
    elif alert_type == "Credential Stuffing":
        return "Block IP and monitor affected accounts"
    elif alert_type == "Possible Account Compromise":
        return "Reset password and investigate account activity"
    return "Investigate further"


def generate_report(alerts):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n=== SOC Threat Detection Report ===")
    print(f"Generated: {now}")
    print(f"Total Alerts: {len(alerts)}")

    if not alerts:
        print("\nNo threats detected.\n")
        return

    print("\nAlerts:\n")

    for i, alert in enumerate(alerts, 1):
        print(f"[{i}] {alert['type']}")
        print(f"    Severity : {alert['severity']}")
        print(f"    IP       : {alert['ip']}")

        if 'user' in alert:
            print(f"    User     : {alert['user']}")

        print(f"    Details  : {alert['details']}")
        print(f"    Action   : {get_action(alert['type'])}")
        print("")


def save_report(alerts, output_file):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_file, "w") as f:
        f.write("SOC Threat Detection Report\n")
        f.write(f"Generated: {now}\n")
        f.write(f"Total Alerts: {len(alerts)}\n\n")

        for i, alert in enumerate(alerts, 1):
            f.write(f"[{i}] {alert['type']}\n")
            f.write(f"Severity: {alert['severity']}\n")
            f.write(f"IP: {alert['ip']}\n")

            if 'user' in alert:
                f.write(f"User: {alert['user']}\n")

            f.write(f"Details: {alert['details']}\n")
            f.write(f"Action: {get_action(alert['type'])}\n")
            f.write("-" * 40 + "\n")

    print(f"\nReport saved to {output_file}")