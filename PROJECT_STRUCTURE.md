# 📁 Project Structure
mhzaly-domain-recon/
├── domain_recon_app.py # Main Streamlit app
├── requirements.txt # Dependencies
├── setup.sh # Setup script
├── .env.example # Config template
├── .gitignore # Git ignore
├── LICENSE # MIT License
├── README.md # Documentation
├── QUICKSTART.md # Quick start
├── CONTRIBUTING.md # Contributing guide
├── ROADMAP.md # Future plans
├── CHANGELOG.md # Version history
├── PROJECT_STRUCTURE.md # This file
├── Dockerfile # Docker image
├── docker-compose.yml # Docker Compose
└── .github/
├── workflows/
│ └── ci.yml # GitHub Actions
└── ISSUE_TEMPLATE/
├── bug_report.md
└── feature_request.md


---

## Architecture

User → Streamlit UI → Core Functions → AI Analysis → Export
↓ ↓
Deterministic Recon Claude API
(DNS, SSL, WHOIS) (Risk, Vulns)

---

## Key Functions

- `get_dns_records()` — DNS queries
- `get_ssl_certificate()` — SSL parsing
- `get_whois_info()` — WHOIS lookup
- `run_subfinder()` — Subdomain enum
- `get_tech_stack()` — Tech detection
- `ai_risk_analysis()` — Claude AI analysis
