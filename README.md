# Network Traffic Analyzer

This is a Python-based network traffic analyzer built using **Scapy** and **Matplotlib**. It captures and analyzes network traffic, displays packet details, and checks for suspicious activity. It also includes:

- **Real-time graphical display** of network protocols.
- **Live monitoring** with the ability to stop the capture manually.
- **Logging** of captured packets into a `.csv` file for future analysis.

## Features

- Capture live network packets continuously.
- Real-time graph showing protocol distribution.
- Analyze and log IP addresses, ports, and protocols.
- Detect suspicious activity (e.g., DDoS or port scanning).
- Log captured data to a `.csv` file.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/IncognitoJR-007/network-traffic-analyzer.git
   cd network-traffic-analyzer
2. Install dependencies
   ```bash
   pip install -r requirements.txt
3. Run the application:
   ```bash
   python app.py

## Usage

1. **Enter Network Interface:** When prompted, enter the name of the network interface you want to monitor (e.g., `eth0`, `wlan0`).
2. **Start Capture:** The tool will start capturing packets and updating the real-time graph.
3. **Stop Capture:** Press `Ctrl+C` to stop the capture.
4. **View Captured Data:** The captured data is saved in the file `network_traffic_log.csv`. You can use a spreadsheet or data analysis tool to explore the data further.

## License

This project is licensed under the MIT License.

### Final Thoughts

Now your **Network Traffic Analyzer** can:

- Capture packets **continuously**.
- Show real-time **graphical insights** of protocol usage with **Matplotlib**.
- Log all network activity into a **CSV file** for future review.
- Detect potential **suspicious activity** like port scanning or DDoS attacks.
