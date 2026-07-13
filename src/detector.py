from datetime import datetime, timedelta

# CONFIG
BRUTE_FORCE_THRESHOLD = 3
BRUTE_FORCE_WINDOW = 60  # seconds

CREDENTIAL_USER_THRESHOLD = 3
CREDENTIAL_WINDOW = 120  # seconds

BREACH_WINDOW = 120  # minutes


def parse_time(ts):
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")


def parse_log_line(line):
    parts = line.strip().split(" | ")
    if len(parts) != 6:
        return None

    return {
        "timestamp": parts[0],
        "level": parts[1],
        "ip": parts[2],
        "eventid": parts[3],
        "user": parts[4].replace("User:", ""),
        "action": parts[5]
    }


def load_logs(filename):
    logs = []
    with open(filename, "r") as file:
        for line in file:
            parsed = parse_log_line(line)
            if parsed:
                logs.append(parsed)
    return logs


# 🔥 BRUTE FORCE DETECTION
def detect_brute_force(logs):
    attempts = {}
    alerts = []

    for log in logs:
        if log["eventid"] == "EventID:4625":
            key = (log["ip"], log["user"])
            time = parse_time(log["timestamp"])
            attempts.setdefault(key, []).append(time)

    for (ip, user), times in attempts.items():
        times.sort()

        for i in range(len(times) - (BRUTE_FORCE_THRESHOLD - 1)):
            if (times[i + BRUTE_FORCE_THRESHOLD - 1] - times[i]).seconds <= BRUTE_FORCE_WINDOW:
                alerts.append({
                    "type": "Brute Force",
                    "ip": ip,
                    "user": user,
                    "severity": "HIGH",
                    "details": f"{BRUTE_FORCE_THRESHOLD}+ failed logins within {BRUTE_FORCE_WINDOW}s"
                })
                break

    return alerts


# 🔥 CREDENTIAL STUFFING DETECTION
def detect_credential_stuffing(logs):
    alerts = []
    ip_activity = {}

    for log in logs:
        if log["eventid"] == "EventID:4625":
            ip = log["ip"]
            time = parse_time(log["timestamp"])
            user = log["user"]

            ip_activity.setdefault(ip, []).append((time, user))

    for ip, entries in ip_activity.items():
        entries.sort()

        for i in range(len(entries)):
            start_time = entries[i][0]
            users = set()

            for j in range(i, len(entries)):
                if (entries[j][0] - start_time).seconds <= CREDENTIAL_WINDOW:
                    users.add(entries[j][1])

            if len(users) >= CREDENTIAL_USER_THRESHOLD:
                alerts.append({
                    "type": "Credential Stuffing",
                    "ip": ip,
                    "severity": "CRITICAL",
                    "details": f"Multiple users targeted: {', '.join(users)}"
                })
                break

    return alerts


# 🔥 POSSIBLE ACCOUNT COMPROMISE DETECTION
def detect_successful_breach(logs):
    alerts = []
    failed_attempts = {}

    # collect failed attempts
    for log in logs:
        if log["eventid"] == "EventID:4625":
            ip = log["ip"]
            time = parse_time(log["timestamp"])
            failed_attempts.setdefault(ip, []).append(time)

    # check success after failures
    for log in logs:
        if log["eventid"] == "EventID:4624":
            ip = log["ip"]
            success_time = parse_time(log["timestamp"])

            if ip in failed_attempts:
                for fail_time in failed_attempts[ip]:
                    diff = success_time - fail_time

                    if timedelta(seconds=0) < diff <= timedelta(minutes=BREACH_WINDOW):
                        alerts.append({
                            "type": "Possible Account Compromise",
                            "ip": ip,
                            "user": log["user"],
                            "severity": "CRITICAL",
                            "details": "Failed login attempts followed by successful login"
                        })
                        break

    return alerts


def run_all_detections(filename):
    logs = load_logs(filename)

    alerts = []
    alerts.extend(detect_brute_force(logs))
    alerts.extend(detect_credential_stuffing(logs))
    alerts.extend(detect_successful_breach(logs))

    return alerts