# Soph's Intrusion Detection System (IDS) 🚨🛡️

Welcome to Soph's Intrusion Detection System (IDS)! This Python and Flask-based project is designed to monitor network traffic for suspicious activity and provide real-time alerts through a web interface.

## Features

- **Network Traffic Monitoring**: Continuously scans network traffic for suspicious port activity.
- **Real-Time Alerts**: Logs alerts for detected suspicious activities and displays them through a web interface.
- **Web Interface**: Access alerts in real-time via a simple web interface at `http://localhost:5000`.

## Installation

To set up the project on your local machine, follow these steps:

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/securesoph/sophsidscript.git
   cd sophsidscript

2. **Install Dependencies:**

Ensure you have Python and pip installed. Install the required Python packages using:
pip install -r requirements.txt

3. **Usage:**
To start the IDS and the web server:

- Run the IDS and Web Server:
python sophsidscript.py

- View Alerts:

Open your web browser and navigate to http://localhost:5000 to view the IDS alerts.

**Code Overview:**
The project includes the following key components:

- Packet Detection: Uses Scapy to detect packets and log any suspicious activity related to predefined ports.
- Alert Management: Logs alerts to ids.log and alerts.txt, and displays them via a Flask web application.
- Web Interface: A simple Flask app renders the alerts in a user-friendly format.

**Contributing**
Contributions are welcome! To contribute:

- Fork the Repository.
- Create a Feature Branch.
- Submit a Pull Request with your improvements.

**License:**
This project is licensed under the MIT License - see the LICENSE file for details.
