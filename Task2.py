from datetime import timedelta
from collections import defaultdict

incidents = []
LOGFILE = "sample_auth_small.log"

def parse_auth_line(line):
    # Use the same code as in Task1.py
    parts = line.split()
    ts_str = " ".join(parts[0:3])
    from datetime import datetime
    try:
        ts = datetime.strptime(f"2025 {ts_str}", "%Y %b %d %H:%M:%S")
    except Exception:
        ts = None
    ip = None
    event_type = "other"
    if "Failed password" in line:
        event_type = "failed"
    elif "Accepted password" in line or "Accepted publickey" in line:
        event_type = "accepted"
    if " from " in line:
        try:
            idx = parts.index("from")
            ip = parts[idx+1]
        except (ValueError, IndexError):
            ip = None
    return ts, ip, event_type

per_ip_timestamps = defaultdict(list)
with open(LOGFILE) as f:
    for line in f:
        ts, ip, event = parse_auth_line(line)
        if ts and ip and event == "failed":
            per_ip_timestamps[ip].append(ts)

#end of code from Task1.py

window = timedelta(minutes=10)
print("Detected Brute forced incidents")
for ip, times in per_ip_timestamps.items():
    times.sort()
    n = len(times)
    i = 0
    while i < n:
        j = i
        while j + 1 < n and (times[j+1] - times[i]) <= window:
            j += 1
        count = j - i + 1
        if count >= 5:
            incidents.append({
                "ip": ip,
                "count": count,
                "first": times[i].isoformat(),
                "last": times[j].isoformat()
            })

            for incident in incidents:       
                print(f"'ip': {incident['ip']}, 'count': {incident['count']}, 'first': {incident['first']}, 'last;: {incident['last']}")

            i = j + 1
        else:
            i += 1