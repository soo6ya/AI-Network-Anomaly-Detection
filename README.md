# 🛡️ AI Network Anomaly Detection Tool

A real-time Windows network monitoring and anomaly detection application powered by **Machine Learning, Scapy, and Streamlit**.

The tool captures live network traffic, extracts traffic features, analyzes network behavior using a trained **Isolation Forest** model, and identifies potentially anomalous activity in real time.

---

## 🚀 Features

- 🔴 Real-time network packet capture
- 🤖 AI-based anomaly detection
- 📊 Live network traffic dashboard
- 📈 Traffic statistics and analysis
- 🧠 Isolation Forest machine-learning model
- 🌐 TCP / UDP traffic analysis
- 🎯 Destination and port analysis
- 🔔 Anomaly alerts
- 🖥️ Standalone Windows executable
- ⚡ No Python installation required for the Windows release

---

## 🖥️ Dashboard

![NetworkTool Dashboard](screenshots/dashboard.png)

The dashboard provides:

- Packet count
- Traffic volume
- TCP / UDP statistics
- Unique destinations
- Source and destination ports
- Anomaly score
- Normal / Anomaly status
- Live monitoring information

---

# 📥 Installation

## 🪟 Windows Requirements

Before running NetworkTool, make sure you have:

- Windows 10 or Windows 11
- **Npcap**
- Administrator privileges

---

## 1️⃣ Install Npcap

NetworkTool uses **Scapy** for live packet capture.

Npcap is required for NetworkTool to capture network traffic on Windows.

### Download Npcap

👉 **[Official Npcap website](https://npcap.com/)**

Install Npcap before launching NetworkTool.

### Recommended Npcap installation

During installation, use the default settings unless you have a specific reason to change them.

---

## 2️⃣ Download NetworkTool

Go to the GitHub **Releases** page and download the latest Windows release:

**NetworkTool-Windows-v1.1.0.zip**

---

## 3️⃣ Extract the ZIP

Extract the downloaded ZIP file to a folder of your choice.

Example:

```text
NetworkTool/
├── NetworkTool.exe
└── _internal/
```

---

## 4️⃣ Run NetworkTool as Administrator

Right-click:

```text
NetworkTool.exe
```

and select:

**Run as administrator**

Administrator privileges may be required for live packet capture.

---

## ⚠️ Windows SmartScreen Warning

Because NetworkTool is a self-built Windows application and is not digitally signed, Windows SmartScreen may display a warning such as:

> Windows protected your PC

If you trust the application:

1. Click **More info**
2. Click **Run anyway**

This allows Windows to launch NetworkTool.

---

## 5️⃣ Open the Dashboard

NetworkTool automatically starts the local dashboard.

Open:

```text
http://127.0.0.1:8501
```

The application uses **port 8501** for the local dashboard.

---

# ▶️ Start Monitoring

Once the dashboard is open:

1. Click **START MONITORING**
2. NetworkTool starts live packet capture
3. Traffic features are extracted
4. The machine-learning model analyzes the traffic
5. The dashboard updates with live results

Example:

```text
Network monitoring started.
MONITORING STARTED SUCCESSFULLY
```

---

# 🤖 AI Anomaly Detection

NetworkTool uses an **Isolation Forest** machine-learning model to identify unusual network traffic.

The system analyzes features such as:

- Packet count
- Total bytes
- Average packet size
- TCP packet count
- UDP packet count
- Unique destinations
- Unique source ports
- Unique destination ports

Each traffic window receives an anomaly score and classification.

Example:

```text
Status: Normal
```

or:

```text
Status: Anomaly
```

---

# 🧪 Scenario Testing

NetworkTool was tested using multiple network-traffic scenarios.

## Scenario 1 — Normal Network Activity

Normal browsing and regular network communication are generated.

Expected behavior:

```text
Status: Normal
```

---

## Scenario 2 — High Traffic Activity

Higher-than-normal network traffic is generated.

The system observes:

- Increased packet count
- Increased traffic volume
- Changes in connection behavior

The AI model analyzes the resulting traffic windows.

---

## Scenario 3 — Suspicious / Anomalous Traffic

A controlled traffic scenario is generated to test the anomaly-detection capability.

Expected behavior:

```text
Anomaly detected
```

The dashboard displays the corresponding anomaly score and traffic information.

> Scenario testing is performed in a controlled environment for demonstration and evaluation purposes.

---

# 📊 Example Detection Output

Example console output:

```text
Window:
{
    'packet_count': 191,
    'total_bytes': 13663,
    'tcp_count': 189,
    'udp_count': 0,
    'unique_destinations': 5,
    'unique_source_ports': 8,
    'unique_destination_ports': 8,
    'anomaly_score': 0.0919,
    'status': 'Normal'
}
```

The dashboard provides a more user-friendly visualization of this information.

---

# 🛠️ Troubleshooting

## NetworkTool does not start

Make sure:

- Npcap is installed
- Windows Defender/SmartScreen has allowed the application
- You are running NetworkTool as Administrator

---

## "Windows protected your PC"

Click:

```text
More info
↓
Run anyway
```

---

## Dashboard does not open

Manually open:

```text
http://127.0.0.1:8501
```

Make sure NetworkTool.exe is still running.

---

## START MONITORING does not work

Check that:

- Npcap is installed
- NetworkTool was started as Administrator
- Your network adapter is active

---

## No network traffic appears

Make sure:

- You are connected to a network
- Npcap is installed correctly
- NetworkTool has the required permissions
- You are generating some network activity

Try opening a website or streaming a video after clicking **START MONITORING**.

---

# 🧑‍💻 Running From Source

If you want to run the project from source instead of using the Windows executable:

### Clone the repository

```bash
git clone https://github.com/soo6ya/AI-Network-Anomaly-Detection.git
cd AI-Network-Anomaly-Detection
```

### Create a virtual environment

```bash
python -m venv venv
```

### Activate it

Windows:

```cmd
venv\Scripts\activate
```

### Install dependencies

```cmd
pip install -r requirements.txt
```

### Run the dashboard

```cmd
python launcher.py
```

The dashboard will be available at:

```text
http://127.0.0.1:8501
```

---

# 📦 Windows Release

### Latest Release

**NetworkTool v1.1.0**

Windows package:

```text
NetworkTool-Windows-v1.1.0.zip
```

### Requirements

```text
Windows 10 / Windows 11
Npcap
Administrator privileges
```

Python and the project dependencies are **not required** when using the standalone Windows release.

---

# 🧰 Technologies Used

- Python
- Streamlit
- Scapy
- Scikit-learn
- Isolation Forest
- Pandas
- NumPy
- Joblib
- Winotify
- PyInstaller

---

# 🏗️ Project Structure

```text
AI-Network-Anomaly-Detection/
│
├── dashboard.py
├── launcher.py
├── live_engine.py
├── live_capture.py
├── live_monitor.py
├── live_predict.py
├── live_ai_monitor.py
│
├── feature_engineering.py
├── train_model.py
├── predict.py
├── analyze_anomalies.py
├── visualize_results.py
│
├── network_anomaly_model.pkl
├── scenario3_test.py
├── test_analysis.py
│
├── requirements.txt
├── README.md
│
└── screenshots/
    └── dashboard.png
```

---

# 🔐 Privacy

NetworkTool performs network monitoring locally on the machine where it is running.

Captured traffic information is processed locally by the application.

The tool does not require a cloud server for its live monitoring functionality.

---

# ⚠️ Disclaimer

This project is intended for:

- Educational purposes
- Research
- Network monitoring
- Machine-learning experimentation
- Authorized testing

Only monitor networks and devices that you own or have explicit permission to analyze.

---

# 👨‍💻 Author

**Surya Dev A**

BCA Student | Network & IT Enthusiast

GitHub:

https://github.com/soo6ya

---

# ⭐ Support

If you find this project useful, consider giving the repository a ⭐ on GitHub.

---

## 📜 License

This project is intended for educational and research purposes.
