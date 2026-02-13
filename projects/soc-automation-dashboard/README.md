# SOC Automation Dashboard

## 🛡️ Enterprise-Grade Security Operations Center Automation Platform

A production-ready, full-stack SOC automation dashboard that demonstrates modern cybersecurity operations, threat intelligence, and incident response automation.

![Dashboard Preview](https://img.shields.io/badge/Status-Production%20Ready-green)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey)
![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Deployed-success)
![License](https://img.shields.io/badge/License-MIT-yellow)

**🌐 Live Demo**: [View Dashboard on GitHub Pages](https://namitranjan.github.io/MyPortfolio/)

---

## ✨ Latest Enhancements (v2.0)

### 300%+ More Security Data
- **50 Alerts** (up from 12) - Comprehensive security scenarios
- **35 Threats** (up from 10) - Diverse threat types including APT, ransomware, phishing
- **25 Incidents** (up from 6) - Multi-severity incident cases
- **150 IOCs** (up from 15) - Extensive threat intelligence database
- **260+ Total Records** - Full-fledged enterprise SOC data

### New Features

#### 🧑‍💼 SOC Team Management
- **12 Team Members** with complete profiles
- Role-based organization (Manager, T1/T2/T3 Analysts, Threat Hunters)
- Real-time status tracking (Online, Away, Offline)
- Individual performance metrics and certifications
- Shift scheduling and coverage tracking

#### 🛡️ Threat Intelligence Feeds
- **5 Active Threat Feeds**:
  - AlienVault OTX (1,247 pulses, 15,832 indicators)
  - AbuseIPDB (892 malicious IPs)
  - VirusTotal (real-time scanning)
  - Emerging Threats (8,942 rules)
  - MISP (523 events)
- Recent threat intelligence updates
- Feed health monitoring
- Automated IOC enrichment

#### 🌐 GitHub Pages Deployment
- **Static Site Deployment** - No backend required
- **Mock API Layer** - Full functionality with static data
- **CI/CD Pipeline** - Automated deployment via GitHub Actions
- **Fast & Responsive** - Optimized for performance

---

## 🌟 Features

### Real-Time Security Monitoring
- **Live Dashboard**: Real-time security event monitoring with automatic updates
- **Security Metrics**: Key performance indicators including MTTR, automation rate, and threat statistics
- **Activity Feed**: Continuous stream of security events and alerts
- **Global Threat Map**: Geographic visualization of threat origins

### Automated Threat Detection
- **Alert Correlation**: Intelligent correlation of security alerts across multiple sources
- **Threat Intelligence**: Integration with threat intel feeds and IOC databases
- **Risk Scoring**: Automated risk assessment for security events
- **MITRE ATT&CK Mapping**: Automatic mapping to MITRE ATT&CK framework tactics

### Incident Response Automation
- **Automated Investigation**: One-click automated investigation playbooks
- **Response Playbooks**: Pre-configured automated response actions
- **Case Management**: Comprehensive incident tracking and management
- **Evidence Collection**: Automated collection of forensic artifacts

### Advanced Analytics
- **Interactive Charts**: Real-time visualization of security data
- **Trend Analysis**: Historical analysis of security events
- **Performance Metrics**: SOC efficiency and automation metrics
- **Custom Reporting**: Exportable reports and dashboards

---

## 🏗️ Architecture

```
soc-automation-dashboard/
├── backend/                  # Python Flask REST API
│   ├── app.py               # Main application server
│   └── requirements.txt     # Python dependencies
├── frontend/                # Modern web interface
│   ├── index.html          # Main dashboard page
│   ├── style.css           # Professional styling
│   └── app.js              # Interactive JavaScript
├── data/                    # Dummy security data
│   ├── alerts.json         # Security alerts
│   ├── threats.json        # Threat intelligence
│   ├── incidents.json      # Security incidents
│   └── iocs.json           # Indicators of Compromise
├── docs/                    # Documentation
│   ├── API.md              # API documentation
│   ├── DEPLOYMENT.md       # Deployment guide
│   └── USAGE.md            # User guide
├── Dockerfile              # Container configuration
├── docker-compose.yml      # Multi-container setup
└── README.md               # This file
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Modern web browser (Chrome, Firefox, Edge)

### Installation

1. **Clone the repository**
```bash
cd projects/soc-automation-dashboard
```

2. **Install dependencies**
```bash
cd backend
pip install -r requirements.txt
```

3. **Start the backend server**
```bash
python app.py
```
The server will start on `http://localhost:5000`

4. **Open the dashboard**
Open `frontend/index.html` in your browser or serve it with:
```bash
cd frontend
python -m http.server 8080
```
Then navigate to `http://localhost:8080`

---

## 🐳 Docker Deployment

### Using Docker Compose (Recommended)

```bash
docker-compose up -d
```

### Manual Docker Build

```bash
# Build the image
docker build -t soc-dashboard .

# Run the container
docker run -d -p 5000:5000 -p 8080:8080 soc-dashboard
```

Access the dashboard at `http://localhost:8080`

---

## 📊 Dashboard Components

### 1. **Dashboard Overview**
- Critical security metrics at a glance
- Real-time event timeline
- Alert distribution charts
- Global threat map

### 2. **Alerts Management**
- Comprehensive alert listing
- Severity-based filtering
- Status tracking
- One-click investigation

### 3. **Threat Intelligence**
- Active threat tracking
- IOC management
- Threat actor attribution
- Geographic threat distribution

### 4. **Incident Response**
- Active incident tracking
- Response action history
- Affected system mapping
- Timeline visualization

### 5. **Automation Playbooks**
- Pre-configured response playbooks
- Success rate metrics
- Execution time statistics
- Trigger conditions

---

## 🔧 API Endpoints

### Dashboard
- `GET /api/dashboard/stats` - Overall statistics
- `GET /api/timeline` - Security event timeline
- `GET /api/threat-map` - Geographic threat data

### Alerts
- `GET /api/alerts` - List all alerts
- `POST /api/alerts/{id}/investigate` - Trigger investigation
- `POST /api/alerts/{id}/respond` - Execute response

### Threats
- `GET /api/threats` - List detected threats
- `GET /api/iocs` - List indicators of compromise

### Incidents
- `GET /api/incidents` - List security incidents

### Playbooks
- `GET /api/playbooks` - List automation playbooks
- `GET /api/metrics/performance` - SOC performance metrics

See [API.md](docs/API.md) for detailed API documentation.

---

## 🎯 Use Cases

1. **Security Operations Center (SOC)**
   - Real-time monitoring of security events
   - Automated alert triage and investigation
   - Incident response coordination

2. **Threat Intelligence Platform**
   - IOC tracking and management
   - Threat actor attribution
   - Intelligence sharing

3. **Security Training**
   - Learn SOC operations
   - Practice incident response
   - Understand security automation

4. **Portfolio Demonstration**
   - Showcase security skills
   - Demonstrate automation capabilities
   - Display full-stack development

---

## 🔐 Security Features

- **Automated Threat Detection**: ML-based anomaly detection
- **IOC Enrichment**: Automatic threat intelligence enrichment
- **Playbook Automation**: Pre-configured response playbooks
- **MITRE ATT&CK Integration**: Automatic tactic/technique mapping
- **Evidence Preservation**: Automated forensic data collection
- **Compliance Reporting**: Audit trail and compliance reports

---

## 📈 Performance Metrics

The dashboard tracks key SOC performance metrics:
- **Mean Time to Detect (MTTD)**
- **Mean Time to Respond (MTTR)**
- **Automation Rate**
- **False Positive Rate**
- **Alert Coverage**
- **Incident Resolution Time**

---

## 🛠️ Technology Stack

### Backend
- **Python 3.8+**: Core programming language
- **Flask**: Lightweight web framework
- **Flask-CORS**: Cross-origin resource sharing

### Frontend
- **HTML5/CSS3**: Modern web standards
- **JavaScript (ES6+)**: Interactive functionality
- **Chart.js**: Data visualization
- **Font Awesome**: Icon library

### Data
- **JSON**: Structured security data
- **RESTful API**: Standard API design

---

## 🌐 Production Deployment

### Cloud Platforms

**AWS**
```bash
# Use Elastic Beanstalk or ECS
eb init -p python-3.8 soc-dashboard
eb create soc-dashboard-env
```

**Azure**
```bash
# Use App Service
az webapp up --name soc-dashboard --runtime PYTHON:3.8
```

**Google Cloud**
```bash
# Use App Engine
gcloud app deploy
```

See [DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed deployment instructions.

---

## 📝 Configuration

### Environment Variables

```bash
# Backend Configuration
FLASK_ENV=production
FLASK_HOST=0.0.0.0
FLASK_PORT=5000

# Frontend Configuration
API_BASE_URL=http://localhost:5000/api
```

### Customization

- **Alerts**: Modify `data/alerts.json` to customize alert data
- **Threats**: Update `data/threats.json` for threat intelligence
- **Styling**: Edit `frontend/style.css` for custom branding
- **Features**: Extend `backend/app.py` for additional endpoints

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 👤 Author

**Namit Ranjan**
- LinkedIn: [namit-ranjan-cybersecurity](https://linkedin.com/in/namit-ranjan-cybersecurity)
- GitHub: [@NamitRanjan](https://github.com/NamitRanjan)
- Portfolio: [MyPortfolio](https://github.com/NamitRanjan/MyPortfolio)

---

## 🙏 Acknowledgments

- MITRE ATT&CK Framework for threat taxonomy
- OWASP for security best practices
- Security community for threat intelligence
- Open-source community for tools and libraries

---

## 📞 Support

For questions, issues, or suggestions:
- Open an issue on GitHub
- Contact via LinkedIn
- Email: namit.ranjan@example.com

---

## 🎓 Learning Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS SOC Resources](https://www.sans.org/security-operations-center/)
- [Threat Intelligence Fundamentals](https://www.crowdstrike.com/cybersecurity-101/threat-intelligence/)

---

**Built with 💙 for the cybersecurity community**
