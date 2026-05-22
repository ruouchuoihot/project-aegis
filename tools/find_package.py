import sys, json
data = json.load(sys.stdin)
for item in data.get('items', []):
    if item['name'] == 'fleet_server':
        print(f"Name: {item['name']}, Version: {item['version']}, Status: {item['status']}")
