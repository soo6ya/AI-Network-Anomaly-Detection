\# 🌐 Network Tool



\## AI-Based Network Anomaly Detection and Real-Time Monitoring



Network Tool is an AI-powered network monitoring application that captures live network traffic, extracts traffic features, detects anomalous behavior using an Isolation Forest machine-learning model, and provides contextual security analysis with real-time Windows notifications.



The system is designed to distinguish legitimate high-volume network activity from potentially suspicious traffic and reduce false-positive alerts.



\---



\## ✨ Features



\- 🔍 Real-time network packet monitoring

\- 🤖 Isolation Forest anomaly detection

\- 📊 Traffic feature engineering

\- 🧠 Context-aware anomaly analysis

\- 🔔 Windows desktop notifications

\- 📈 Live Streamlit dashboard

\- 🧾 Security alert history

\- 🌐 Npcap/Scapy packet capture

\- 🛡️ Multi-window suspicious-traffic detection

\- 👨‍💻 Windows executable version



\---



\## 🏗️ System Architecture



```text

Network Traffic

&#x20;      │

&#x20;      ▼

&#x20;Scapy + Npcap

&#x20;      │

&#x20;      ▼

&#x20;Packet Capture

&#x20;      │

&#x20;      ▼

&#x20;1-Second Windows

&#x20;      │

&#x20;      ▼

Feature Engineering

&#x20;      │

&#x20;      ▼

Traffic Features

&#x20;      │

&#x20;      ▼

Isolation Forest

&#x20;      │

&#x20;      ▼

Anomaly Detection

&#x20;      │

&#x20;      ▼

Contextual Analysis

&#x20;      │

&#x20;      ├───────────────┐

&#x20;      ▼               ▼

&#x20;   Normal         Suspicious

&#x20;                      │

&#x20;                      ▼

&#x20;               Windows Notification

&#x20;                      │

&#x20;                      ▼

&#x20;               Streamlit Dashboard

🧠 Machine Learning



The project uses the Isolation Forest algorithm for unsupervised anomaly detection.



The model learns patterns from normal network traffic and identifies traffic windows that significantly differ from the learned baseline.



Traffic features



The model uses features including:



Packet count

Total bytes

Average packet size

TCP count

UDP count

Unique destinations

Unique source ports

Unique destination ports

IPv4 count

IPv6 count

Packets per second

Bytes per second

TCP ratio

UDP ratio

📊 Dataset Pipeline



Normal network activity was collected from several types of traffic:



Web browsing

Downloads

Video streaming

Speed tests

High-speed traffic

General network traffic



The captured packets are cleaned, duplicate packets are removed, and the resulting traffic is converted into time-based feature windows.



🛡️ Contextual Detection



A machine-learning anomaly does not automatically generate a security notification.



The system combines multiple indicators:



Traffic volume

Packet rate

Source-port diversity

Destination-port diversity

Isolation Forest anomaly score

Repeated anomalous windows



This prevents legitimate activities such as:



YouTube

Gmail

Multiple browser tabs

Downloads

Speed tests



from automatically being treated as security threats.



🧪 Testing



The system was tested using three main scenarios.



Scenario	Expected Result	Result

YouTube + multiple browser tabs	No security notification	✅ Passed

High-speed/data traffic	No security notification	✅ Passed

Controlled suspicious traffic	Security notification	✅ Passed

📁 Project Structure

AI-Network-Anomaly-Detection/

│

├── dashboard.py

├── live\_engine.py

├── network\_anomaly\_model.pkl

│

├── dataset\_manager.py

├── feature\_engineering.py

├── train\_model.py

│

├── normal\_activity\_capture.py

├── packet\_capture.py

├── scenario3\_test.py

│

├── analyze\_anomalies.py

├── live\_ai\_monitor.py

├── live\_capture.py

├── live\_monitor.py

├── live\_predict.py

├── predict.py

├── test\_analysis.py

├── visualize\_results.py

│

├── requirements.txt

├── README.md

└── .gitignore

💻 Running From Source

1\. Clone the repository

git clone https://github.com/soo6ya/AI-Network-Anomaly-Detection.git

cd AI-Network-Anomaly-Detection

2\. Create a virtual environment

python -m venv venv

3\. Activate the environment



Windows:



venv\\Scripts\\activate

4\. Install dependencies

pip install -r requirements.txt

5\. Start the Network Tool

streamlit run dashboard.py

⚠️ Requirements

Operating System



Windows is currently the primary supported platform.



Npcap



Network packet capture requires Npcap.



Npcap must be installed separately on the computer running the application.



Loopback traffic monitoring may require the Npcap Loopback Adapter.



🔔 Windows Notifications



The application uses Windows desktop notifications to alert the user when strong suspicious network activity is detected.



Normal high-volume traffic does not automatically trigger a security notification.



🧪 Controlled Testing



The repository includes a local controlled traffic test:



python scenario3\_test.py



The test targets:



127.0.0.1



and is intended for testing the detection system on the local machine.



👨‍💻 Developer

Soo6ya



GitHub:



https://github.com/soo6ya



⚖️ Disclaimer



This project is intended for educational, research, and defensive network-monitoring purposes.



Only monitor network traffic on systems and networks that you own or have explicit permission to monitor.



📄 License



This project is currently provided for educational and personal development purposes.

