import os, time, json, random, string, datetime, sys, http.client, base64
from urllib.parse import urlparse

# --- Configuration from Environment ---
ES_URL = os.environ.get("ES_URL", "https://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "changeme")
CA_CERT = os.environ.get("CA_CERT", "config/certs/ca/ca.crt")
INDEX = "logs-aegis-simulation-default"

# --- MITRE ATT&CK Mapping Helpers ---
def get_timestamp():
    return datetime.datetime.utcnow().isoformat() + "Z"

def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def rand_id(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

# --- Attack Scenario Generators ---

def simulate_ransomware_precursor():
    """T1486: Data Encrypted for Impact (Precursor: Discovery & Shadow Copy Deletion)"""
    host = "win-prod-srv-01"
    pid = random.randint(1000, 9999)
    events = [
        # Discovery: Process Discovery
        {
            "@timestamp": get_timestamp(),
            "ecs": {"version": "8.11.0"},
            "message": "Process tasklist.exe executed for discovery purposes",
            "event": {"kind": "event", "category": ["process", "host"], "type": ["start", "info"], "action": "executed", "module": "aegis", "dataset": "simulation"},
            "process": {"name": "tasklist.exe", "command_line": "tasklist /v", "pid": pid},
            "host": {"hostname": host, "name": host},
            "threat": {"technique": {"id": "T1057", "name": "Process Discovery"}}
        },
        # Impact: Inhibit System Recovery (Delete Shadow Copies)
        {
            "@timestamp": get_timestamp(),
            "ecs": {"version": "8.11.0"},
            "message": "Shadow copies deleted using vssadmin.exe",
            "event": {"kind": "event", "category": ["process", "host"], "type": ["start", "info"], "action": "executed", "module": "aegis", "dataset": "simulation"},
            "process": {"name": "vssadmin.exe", "command_line": "vssadmin.exe delete shadows /all /quiet", "pid": pid+1},
            "host": {"hostname": host, "name": host},
            "threat": {"technique": {"id": "T1490", "name": "Inhibit System Recovery"}}
        }
    ]
    return events

def simulate_lateral_movement():
    """T1021.002: Remote Services: SMB/Windows Admin Shares"""
    src_host = "win-workstation-10"
    dst_ip = rand_ip()
    events = [
        {
            "@timestamp": get_timestamp(),
            "ecs": {"version": "8.11.0"},
            "message": f"Outbound SMB connection to {dst_ip}",
            "event": {"kind": "event", "category": ["network", "host"], "type": ["connection", "info"], "action": "smb_mapping", "module": "aegis", "dataset": "simulation"},
            "source": {"ip": "10.0.5.50", "host": {"name": src_host}},
            "destination": {"ip": dst_ip, "port": 445},
            "network": {"protocol": "smb", "direction": "outbound"},
            "host": {"hostname": src_host, "name": src_host},
            "threat": {"technique": {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares"}}
        }
    ]
    return events

def simulate_persistence_scheduled_task():
    """T1053.005: Scheduled Task/Job: Scheduled Task"""
    host = "linux-app-01"
    events = [
        {
            "@timestamp": get_timestamp(),
            "ecs": {"version": "8.11.0"},
            "message": "Scheduled task created for persistence",
            "event": {"kind": "event", "category": ["process", "host"], "type": ["start", "info"], "module": "aegis", "dataset": "simulation"},
            "process": {"name": "crontab", "command_line": "echo '*/5 * * * * /tmp/.hidden_script' | crontab -"},
            "host": {"hostname": host, "name": host},
            "threat": {"technique": {"id": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task"}}
        }
    ]
    return events

SCENARIOS = [simulate_ransomware_precursor, simulate_lateral_movement, simulate_persistence_scheduled_task]

# --- ELASTICSEARCH COMMUNICATION (HTTPS/Basic Auth) ---
# Note: In a real environment, we would use the 'elasticsearch' python lib for convenience.
# Here we use http.client to keep the container lightweight without extra pip installs.

def bulk_post(actions):
    u = urlparse(ES_URL)
    # Note: This generator bypasses SSL verification for lab simplicity (matching AEGIS_INSECURE settings)
    import ssl
    context = ssl._create_unverified_context()
    
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, context=context, timeout=10)
    body = "\n".join(actions) + "\n"
    headers = {
        "Content-Type": "application/x-ndjson",
        "Authorization": f"Basic {base64.b64encode(f'{ES_USER}:{ES_PASSWORD}'.encode()).decode()}"
    }
    try:
        conn.request("POST", "/_bulk", body=body, headers=headers)
        resp = conn.getresponse()
        if resp.status >= 300:
            print(f"[ERROR] Bulk status: {resp.status} - {resp.read().decode()[:500]}")
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
    finally:
        conn.close()

def main():
    print(f"[*] Project Aegis Simulator started. Target: {ES_URL}")
    while True:
        # Generate multiple scenarios per batch for higher volume
        actions = []
        for _ in range(random.randint(1, 5)):
            scenario = random.choice(SCENARIOS)
            events = scenario()
            for e in events:
                actions.append(json.dumps({"create": {"_index": INDEX}}))
                actions.append(json.dumps(e))
        
        bulk_post(actions)
        # Faster sleep interval
        time.sleep(random.uniform(0.5, 2.0))

if __name__ == "__main__":
    main()
