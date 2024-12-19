import os
import subprocess
import json
import pandas as pd
import matplotlib.pyplot as plt

# Step 1: Define Paths for Configuration
SURICATA_LOG_PATH = "/var/log/suricata/eve.json"  # Path to Suricata logs

# Step 2: Install Suricata if Not Installed (Optional)
def install_suricata():
    print("Installing Suricata...")
    subprocess.run(["sudo", "apt", "update"])
    subprocess.run(["sudo", "apt", "install", "-y", "suricata"])

# Step 3: Start Suricata Monitoring
def start_suricata(interface="eth0"):
    print(f"Starting Suricata on interface {interface}...")
    subprocess.run(["sudo", "suricata", "-c", "/etc/suricata/suricata.yaml", "-i", interface])

# Step 4: Read Suricata Logs
def read_logs():
    if not os.path.exists(SURICATA_LOG_PATH):
        print(f"Log file not found at {SURICATA_LOG_PATH}")
        return []

    with open(SURICATA_LOG_PATH, "r") as log_file:
        logs = [json.loads(line) for line in log_file if line.strip()]
    return logs

# Step 5: Analyze Logs
def analyze_logs(logs):
    df = pd.DataFrame(logs)

    if df.empty:
        print("No data to analyze.")
        return

    print("Sample Data:")
    print(df.head())

    # Count events by category
    event_counts = df["event_type"].value_counts()
    print("Event Counts:")
    print(event_counts)

    # Plot events
    event_counts.plot(kind="bar", title="Event Type Counts")
    plt.xlabel("Event Type")
    plt.ylabel("Count")
    plt.show()

# Step 6: Main Function
def main():
    print("Network Intrusion Detection System")

    # Uncomment to install Suricata if not already installed
    # install_suricata()

    # Uncomment to start monitoring
    # start_suricata(interface="eth0")

    logs = read_logs()
    if logs:
        analyze_logs(logs)
    else:
        print("No logs found to process.")

if __name__ == "__main__":
    main()
