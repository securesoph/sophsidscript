import logging
from scapy.all import sniff, TCP, IP
from flask import Flask, render_template_string
from threading import Thread

# Setting up logging to record all the detected alerts
logging.basicConfig(filename='ids.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# List of suspicious ports to monitor
suspicious_ports = [21, 22, 23, 25, 53, 80, 110, 443]

# Function to detect packets and log suspicious activity
alerts = []

def detect_packet(packet):
    if packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        if dport in suspicious_ports or sport in suspicious_ports:
            alert_message = f"ALERT: Suspicious port activity detected: {sport} -> {dport} from {ip_src} to {ip_dst}"
            print(alert_message)
            alerts.append(alert_message)
            logging.info(alert_message)
            with open("alerts.txt", "a") as alert_file:
                alert_file.write(alert_message + "\n")

# Function to start the IDS on a given network interface
def start_ids(interface):
    print(f"Starting IDS on interface {interface}")
    sniff(iface=interface, prn=detect_packet, store=0)

# Flask web app to display alerts
app = Flask(__name__)

@app.route('/')
def index():
    try:
        with open("alerts.txt", "r") as alert_file:
            alerts = alert_file.readlines()
    except FileNotFoundError:
        alerts = []  # Initialize alerts as an empty list if file doesn't exist
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>IDS Alerts</title>
    </head>
    <body>
        <h1>Intrusion Detection System Alerts</h1>
        <ul>
            {% for alert in alerts %}
                <li>{{ alert }}</li>
            {% endfor %}
        </ul>
    </body>
    </html>
    ''', alerts=alerts)

# Function to run IDS in a separate thread
def run_ids():
    interface = input("Enter network interface to monitor (e.g., eth0, wlan0): ")
    print(f"User entered interface: {interface}")
    start_ids(interface)

if __name__ == "__main__":
    print("Starting IDS and Flask web server")
    # Start IDS in a separate thread
    ids_thread = Thread(target=run_ids, name="IDS_Thread")
    ids_thread.start()
    
    # Start Flask app
    app.run(host='127.0.0.1', port=5000, debug=True)

