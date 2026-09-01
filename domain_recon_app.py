import streamlit as st
import subprocess
import json
import socket
import ssl
import requests
from datetime import datetime
from typing import Dict, List
import pandas as pd
from urllib.parse import urlparse
import google.generativeai as genai
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Page config
st.set_page_config(
    page_title="MHZALY Domain Recon Analyzer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    [data-testid="stMetricValue"] { font-size: 2rem; }
    .status-critical { color: #ff4444; }
    .status-high { color: #ff8800; }
    .status-medium { color: #ffaa00; }
    .status-low { color: #44aa44; }
    .status-info { color: #4488ff; }
</style>
""", unsafe_allow_html=True)

# ==================== UTILITY FUNCTIONS ====================

@st.cache_data(ttl=3600)
def get_dns_records(domain: str) -> Dict:
    """Query DNS records for domain"""
    records = {
        'A': [],
        'MX': [],
        'TXT': [],
        'NS': [],
        'CNAME': [],
        'error': None
    }
    try:
        import dns.resolver
        
        for record_type in records.keys():
            if record_type == 'error':
                continue
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except:
                records[record_type] = []
    except ImportError:
        records['error'] = "dnspython not installed"
    
    return records

@st.cache_data(ttl=3600)
def get_ssl_certificate(domain: str) -> Dict:
    """Extract SSL certificate information"""
    cert_info = {
        'valid': False,
        'issuer': None,
        'subject': None,
        'expiry': None,
        'serial': None,
        'error': None
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                if cert:
                    cert_info['valid'] = True
                    cert_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    cert_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                    cert_info['expiry'] = cert.get('notAfter', 'Unknown')
                    cert_info['serial'] = cert.get('serialNumber', 'Unknown')
    except Exception as e:
        cert_info['error'] = str(e)
    
    return cert_info

@st.cache_data(ttl=3600)
def get_whois_info(domain: str) -> Dict:
    """Get WHOIS information"""
    whois_data = {
        'registrar': None,
        'created': None,
        'expires': None,
        'updated': None,
        'status': None,
        'error': None
    }
    
    try:
        import whois
        w = whois.whois(domain)
        whois_data['registrar'] = str(w.registrar)
        whois_data['created'] = str(w.creation_date) if hasattr(w, 'creation_date') else None
        whois_data['expires'] = str(w.expiration_date) if hasattr(w, 'expiration_date') else None
        whois_data['updated'] = str(w.updated_date) if hasattr(w, 'updated_date') else None
        whois_data['status'] = str(w.status) if hasattr(w, 'status') else None
    except ImportError:
        whois_data['error'] = "whois not installed"
    except Exception as e:
        whois_data['error'] = str(e)
    
    return whois_data

def run_subfinder(domain: str) -> List[str]:
    """Run subfinder for subdomain enumeration"""
    try:
        result = subprocess.run(
            ['subfinder', '-d', domain, '-silent'],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return result.stdout.strip().split('\n')
        else:
            return []
    except FileNotFoundError:
        return []
    except Exception as e:
        return []

def get_tech_stack(domain: str) -> Dict:
    """Detect technologies"""
    techs = {
        'web_servers': [],
        'cms': [],
        'js_frameworks': [],
        'cdn': [],
        'analytics': []
    }
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        try:
            response = requests.get(f'https://{domain}', headers=headers, timeout=10, verify=False)
        except:
            return techs
        
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        content = response.text.lower()
        
        if 'server' in headers_lower:
            techs['web_servers'].append(headers_lower['server'])
        
        if 'wordpress' in content or 'wp-content' in content:
            techs['cms'].append('WordPress')
        if 'drupal' in content:
            techs['cms'].append('Drupal')
        
        if 'react' in content:
            techs['js_frameworks'].append('React')
        if 'angular' in content:
            techs['js_frameworks'].append('Angular')
        
        if 'cloudflare' in content or headers_lower.get('cf-ray'):
            techs['cdn'].append('Cloudflare')
        
        if 'google-analytics' in content:
            techs['analytics'].append('Google Analytics')
        
    except Exception:
        pass
    
    return techs

def ai_risk_analysis(domain: str, findings: Dict, api_key: str) -> Dict:
    """Use Google Gemini AI to analyze findings"""
    analysis = {
        'risk_score': 0,
        'risk_level': 'UNKNOWN',
        'findings': [],
        'recommendations': [],
        'error': None
    }
    
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-pro')
        
        prompt = f"""Analyze this domain security data and respond ONLY with valid JSON (no markdown):
Domain: {domain}
DNS: {json.dumps(findings.get('dns', {}))}
SSL: {json.dumps(findings.get('ssl', {}), default=str)}
Tech: {json.dumps(findings.get('tech_stack', {}))}
Subdomains: {findings.get('subdomains_count', 0)}

Response format:
{{"risk_score": 0-100, "risk_level": "LOW|MEDIUM|HIGH|CRITICAL", "findings": ["finding1"], "recommendations": ["rec1"]}}"""
        
        response = model.generate_content(prompt)
        response_text = response.text.strip()
        
        if response_text.startswith('```'):
            response_text = response_text.split('```')[1]
            if response_text.startswith('json'):
                response_text = response_text[4:]
        response_text = response_text.strip()
        
        ai_result = json.loads(response_text)
        
        analysis['risk_score'] = ai_result.get('risk_score', 0)
        analysis['risk_level'] = ai_result.get('risk_level', 'UNKNOWN')
        analysis['findings'] = ai_result.get('findings', [])
        analysis['recommendations'] = ai_result.get('recommendations', [])
        
    except Exception as e:
        analysis['error'] = str(e)
    
    return analysis

# ==================== MAIN APP ====================

st.title("🔍 MHZALY Domain Recon Analyzer")
st.markdown("**Bug Bounty + Security Intelligence Platform**")

# Sidebar
with st.sidebar:
    st.header("⚙️ Configuration")
    
    api_key = None
    try:
        api_key = st.secrets.get("GEMINI_API_KEY", "")
    except:
        pass
    
    if not api_key:
        api_key = st.text_input("🔑 Gemini API Key", type="password")
    
    st.markdown("---")
    st.info("ℹ️ Get free API key at ai.google.dev")

# Main input
col1, col2 = st.columns([3, 1])
with col1:
    domain = st.text_input("🎯 Enter Domain", placeholder="example.com")
with col2:
    analyze_button = st.button("🚀 Analyze", use_container_width=True)

if analyze_button and domain:
    domain = domain.strip().lower().replace('https://', '').replace('http://', '').replace('www.', '')
    
    st.markdown("---")
    
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🌐 Infrastructure", "🔐 Security", "📋 Report"])
    
    with st.spinner("🔄 Gathering reconnaissance data..."):
        
        findings = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'dns': get_dns_records(domain),
            'ssl': get_ssl_certificate(domain),
            'whois': get_whois_info(domain),
            'tech_stack': get_tech_stack(domain),
            'subdomains': run_subfinder(domain),
        }
        
        findings['subdomains_count'] = len(findings['subdomains'])
        
        ai_analysis = {}
        if api_key:
            ai_analysis = ai_risk_analysis(domain, findings, api_key)
    
    # TAB 1: OVERVIEW
    with tab1:
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if ai_analysis and 'risk_score' in ai_analysis:
                st.metric("Risk Score", f"{ai_analysis['risk_score']}/100")
            else:
                st.metric("Subdomains", findings['subdomains_count'])
        
        with col2:
            if ai_analysis and 'risk_level' in ai_analysis:
                st.metric("Risk Level", ai_analysis['risk_level'])
            else:
                st.metric("DNS Records", len([r for r in findings['dns'].values() if isinstance(r, list) and r]))
        
        with col3:
            tech_count = sum(len(v) if isinstance(v, list) else 0 for v in findings['tech_stack'].values())
            st.metric("Technologies", tech_count)
        
        with col4:
            ssl_status = "✅ Valid" if findings['ssl'].get('valid') else "❌ Invalid"
            st.metric("SSL Status", ssl_status)
        
        st.markdown("---")
        
        if ai_analysis.get('findings'):
            st.subheader("🔴 Key Findings")
            for finding in ai_analysis['findings']:
                st.warning(finding)
    
    # TAB 2: INFRASTRUCTURE
    with tab2:
        st.subheader("📍 Subdomains")
        if findings['subdomains']:
            df = pd.DataFrame({'Subdomain': findings['subdomains']})
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No subdomains found")
        
        st.markdown("---")
        st.subheader("🌐 DNS Records")
        dns_cols = st.columns(3)
        with dns_cols[0]:
            if findings['dns'].get('A'):
                st.write("**A Records**")
                for a in findings['dns']['A']:
                    st.code(a)
        with dns_cols[1]:
            if findings['dns'].get('MX'):
                st.write("**MX Records**")
                for mx in findings['dns']['MX']:
                    st.code(mx)
        with dns_cols[2]:
            if findings['dns'].get('NS'):
                st.write("**NS Records**")
                for ns in findings['dns']['NS']:
                    st.code(ns)
    
    # TAB 3: SECURITY
    with tab3:
        st.subheader("🔐 SSL Certificate")
        if findings['ssl'].get('valid'):
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Issuer:** {findings['ssl'].get('issuer', 'N/A')}")
            with col2:
                st.write(f"**Expiry:** {findings['ssl'].get('expiry', 'N/A')}")
        else:
            st.error(f"SSL Error: {findings['ssl'].get('error', 'Unknown')}")
        
        st.markdown("---")
        st.subheader("🛠 Technologies")
        if findings['tech_stack']:
            for category, techs in findings['tech_stack'].items():
                if techs:
                    st.write(f"**{category.replace('_', ' ').title()}:** {', '.join(techs)}")
    
    # TAB 4: REPORT
    with tab4:
        st.subheader("📊 Summary")
        if ai_analysis:
            if ai_analysis.get('recommendations'):
                st.write("**Recommendations:**")
                for rec in ai_analysis['recommendations']:
                    st.write(f"- {rec}")
        
        st.markdown("---")
        
        json_export = json.dumps({
            **findings,
            'ai_analysis': ai_analysis
        }, indent=2, default=str)
        
        st.download_button(
            "📥 Download Report (JSON)",
            data=json_export,
            file_name=f"{domain}_recon_report.json",
            mime="application/json"
        )

st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #888; font-size: 0.9rem;">
    <p>MHZALY Domain Recon Analyzer | Security Intelligence</p>
</div>
""", unsafe_allow_html=True)
