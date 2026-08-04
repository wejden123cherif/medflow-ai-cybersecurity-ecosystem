#!/var/ossec/framework/python/bin/python3
import sys
import json
import urllib.request
import urllib.error

# Read the arguments passed by Wazuh
# 1st arg: alert file path
alert_file = sys.argv[1]
# 2nd arg: integration user (optional)
# 3rd arg: hook URL (optional, if configured)

MEDFLOW_API_URL = "http://host.docker.internal:8000/webhook/wazuh"

def main():
    try:
        # Read the alert file
        with open(alert_file, 'r') as f:
            alert = json.load(f)

        # Prepare the request
        req = urllib.request.Request(MEDFLOW_API_URL, method="POST")
        req.add_header('Content-Type', 'application/json')
        data = json.dumps(alert).encode('utf-8')

        # Send the webhook
        response = urllib.request.urlopen(req, data=data, timeout=5)
        
        # Log success
        with open("/var/ossec/logs/integrations.log", "a") as log:
            log.write(f"Successfully sent alert to MedFlow API. Status: {response.getcode()}\n")

    except Exception as e:
        with open("/var/ossec/logs/integrations.log", "a") as log:
            log.write(f"Error sending alert to MedFlow API: {str(e)}\n")

if __name__ == "__main__":
    main()
