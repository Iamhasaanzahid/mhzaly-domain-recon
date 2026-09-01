# 🔍 MHZALY Domain Reconnaissance Analyzer

**Bug Bounty + SOC Intelligence Platform**

A comprehensive domain analysis tool that combines **90% deterministic reconnaissance** with **10% AI-powered intelligence** to map infrastructure, detect technologies, assess security posture, and generate attack surface prioritization.

---

## 🎯 Features

### Deterministic Recon (90%)
- ✅ **Subdomain Enumeration** — Uses `subfinder` for comprehensive discovery
- ✅ **DNS Records** — A, MX, NS, TXT, CNAME lookups
- ✅ **SSL Certificate Analysis** — Issuer, expiry, serial, SANs
- ✅ **WHOIS Information** — Registrar, dates, status
- ✅ **Technology Stack Detection** — CMS, frameworks, servers, CDNs, analytics

### AI Intelligence (10%)
- 🤖 **Risk Scoring** — Automatic severity assessment (0-100)
- 🤖 **Vulnerability Suggestions** — Tech-specific attack vectors
- 🤖 **Attack Surface Mapping** — Prioritized exploitation paths
- 🤖 **Testing Recommendations** — Bug bounty testing checklist
- 🤖 **Automated Report Generation** — Executive summaries + export

---

## 📋 Prerequisites

```bash
# Python 3.8+
python3 --version

# Install dependencies
pip install -r requirements.txt

# Optional: Install subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

---

## 🚀 Quick Start

### 1. Install
```bash
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Get API Key
Get free Anthropic API key: https://console.anthropic.com

### 3. Run
```bash
streamlit run domain_recon_app.py
```

Opens at `http://localhost:8501`

---

## 📖 Usage

1. **Enter Domain** → Type `example.com`
2. **Click Analyze** → App gathers data
3. **Review Tabs** → Explore results:
   - 📊 Overview (Risk score, metrics)
   - 🌐 Infrastructure (Subdomains, DNS)
   - 🔐 Security (SSL, tech, WHOIS)
   - 🎯 Attack Surface (Vulnerabilities, priorities)
   - 📋 Report (Export options)
4. **Download Report** → JSON or TXT format

---

## 🔧 Configuration

### Environment Variables
```bash
export ANTHROPIC_API_KEY="sk-ant-xxxxx"
streamlit run domain_recon_app.py
```

### .env File
Copy `.env.example` to `.env` and fill in values

---

## 🐳 Docker

```bash
# Build
docker build -t mhzaly-recon .

# Run
docker run -p 8501:8501 mhzaly-recon

# With Docker Compose
docker-compose up
```

---

## 📊 Output Examples

### Overview Tab
- Risk Score: 78/100
- Risk Level: HIGH
- Technologies: 5 detected
- SSL Status: Valid

### Infrastructure Tab
- Subdomains: 47 discovered
- DNS Records: A, MX, NS, TXT
- Downloadable list

### Attack Surface Tab
- Vulnerabilities: 3 (HIGH, MEDIUM, LOW)
- Attack Paths: 5 identified
- Testing Priorities: 7 recommended

---

## 🎓 Architecture
User Input (Domain)
↓
Deterministic Recon (90%)
├─ DNS queries
├─ SSL parsing
├─ WHOIS lookup
├─ Subfinder scan
└─ Tech detection
↓
AI Analysis (10%)
├─ Risk scoring
├─ Vuln detection
├─ Attack mapping
└─ Report generation
↓
UI Display + Export

---

## 🛠️ Tech Stack

- **Frontend:** Streamlit
- **Backend:** Python 3.8+
- **AI:** Anthropic Claude API
- **Recon:** dnspython, python-whois, subprocess (subfinder)
- **Data:** pandas
- **Deployment:** Docker, Docker Compose

---

## 📈 Future Enhancements

- [ ] Nmap port scanning
- [ ] Shodan API integration
- [ ] Batch domain analysis
- [ ] Database persistence
- [ ] Slack notifications
- [ ] REST API backend

See [ROADMAP.md](ROADMAP.md) for detailed plans.

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## ⚠️ Legal

This tool is for authorized security testing only. Ensure you have permission before scanning any domain.

---

## 📄 License

MIT License - See [LICENSE](LICENSE)

---

## 🙌 Credits

Built for cybersecurity professionals and bug bounty hunters.

**Happy Hunting! 🎯**
