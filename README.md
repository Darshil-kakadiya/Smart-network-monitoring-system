# SmartNet AI-Powered Bandwidth Management System

An innovative network traffic control system with AI-driven predictions, anomaly detection, and automated security features.

## 🚀 Key Features

### AI & Machine Learning
- **Predictive Analytics**: Uses linear regression models to forecast bandwidth usage
- **Anomaly Detection**: Identifies unusual network activity using statistical analysis
- **Smart Health Scoring**: Network health score considers usage patterns and anomalies

### Advanced Network Management
- **Intelligent Scanning**: Nmap integration for detailed device discovery (Linux)
- **One-Click SMART Scan**: Hybrid scan (nmap/arp/ip-neigh/ping sweep) for better real-world discovery
- **Hotspot-Only Device Filtering**: Shows only devices within the active hotspot/wireless subnet
- **Wired/Wireless Labeling**: Detects likely connection type with confidence scoring
- **Automated Blocking**: Auto-blocks devices with anomalous behavior in AUTO mode
- **Priority-Based Bandwidth Allocation**: Role-based limits (Admin, Teacher, Student, Guest)

### Real-Time Monitoring
- **Live Dashboard**: Web-based interface with real-time updates
- **Traffic Visualization**: Chart.js powered usage graphs
- **Alert System**: Proactive notifications for critical events
- **Scan Observability**: Shows last scan mode, scanned subnets, source breakdown, and scan duration

### Security & Automation
- **Multi-Mode Operation**: MANUAL, AUTO, and SMART modes for different security levels
- **Traffic Control**: Linux tc integration for precise bandwidth shaping
- **Audit Logging**: Comprehensive action logging

## 🛠️ Technical Improvements

### Enhanced AI Engine
- Machine learning models trained per device IP
- Fallback to trend analysis when ML unavailable
- Anomaly detection with z-score thresholding

### Improved Scanner
- Nmap scanning for hostname and detailed info
- ARP fallback for cross-platform compatibility
- Dynamic subnet detection from active interface mask (no fixed /24 fallback)
- Multi-interface scanning (scans all detected active subnets)
- Persistent device database with JSON storage

### Better User Experience
- Real-time polling for live updates
- Anomaly alerts in dashboard
- Health score visualization

### Code Quality
- Error handling and graceful degradation
- Cross-platform support (Linux primary, Windows simulation)
- Modular architecture for easy extension

## 📋 Requirements

- Python 3.7+
- Flask
- scikit-learn (optional, for ML features)
- Linux: nmap, tc, iptables (for full functionality)
- Windows: ARP scanning simulation

## 🚀 Installation

1. Clone the repository
2. Install dependencies: `pip install flask scikit-learn`
3. Run: `python app.py`
4. Access: http://localhost:5000

## 🔧 Configuration

Edit `config.py` for:
- Network interface settings
- Scan subnets
- Authentication credentials
- AI parameters

## 📊 Usage

1. Login with admin credentials
2. Switch between MANUAL/AUTO/SMART modes
3. Monitor device usage and predictions
4. Set priorities and block/unblock devices
5. Generate reports

## 📄 Reports

- The dashboard REPORT button now generates a **PDF** report.
- Reports include only currently connected hotspot devices with device names, summary, and usage samples.
- Generated PDFs are downloadable directly from the UI.

## 🔒 Security Features

- Root privilege checks on Linux
- Session-based authentication
- Automatic anomaly blocking in AUTO mode
- Comprehensive logging

## 📈 Future Enhancements

- Real-time WebSocket updates
- External API integrations (weather, time-based policies)
- Advanced ML models (LSTM for time series)
- Mobile API endpoints
- Multi-admin support

This project demonstrates modern network management with AI, making it more effective for educational and enterprise environments.</content>
<parameter name="filePath">d:\project Cn\README.md"# Smart-network-monitoring-system" 
"# Smart-network-monitoring-system" 
"# Smart-network-monitoring-system" 
