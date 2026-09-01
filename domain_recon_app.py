import streamlit as st
import subprocess
import json
import socket
import ssl
import requests
from datetime import datetime
from typing import Dict, List, Tuple
import pandas as pd
from urllib.parse import urlparse
import anthropic
import os
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
        records['error'] = "dnspython not installed. Run: pip install dnspython"
    
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
        'version': None,
        'error': None
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cert_bin = ssock.getpeercert(binary_form=True)
                
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
        whois_data['error'] = "whois not installed. Run: pip install python-whois"
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
        st.warning(f"Subfinder error: {e}")
        return []

def get_tech_stack(domain: str) -> Dict:
    """Detect technologies using manual checks + Wappalyzer logic"""
    techs = {
        'web_servers': [],
        'cms': [],
        'js_frameworks': [],
        'db': [],
        'cdn': [],
        'analytics': [],
        'other': []
    }
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        # FIX: Proper SSL verification with timeout handling
        try:
            response = requests.get(f'https://{domain}', headers=headers, timeout=10, verify=True)
        except requests.exceptions.SSLError:
            # Fallback for self-signed certificates
            response = requests.get(f'https://{domain}', headers=headers, timeout=10, verify=False)
        except requests.exceptions.ConnectionError:
            return techs
        
        # Simple tech detection based on headers and HTML
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        content = response.text.lower()
        
        # Server detection
        if 'server' in headers_lower:
            techs['web_servers'].append(headers_lower['server'])
        
        # Framework detection
        if 'wordpress' in content or 'wp-content' in content:
            techs['cms'].append('WordPress')
        if 'drupal' in content:
            techs['cms'].append('Drupal')
        if 'joomla' in content:
            techs['cms'].append('Joomla')
        
        if 'react' in content or 'react.js' in content:
            techs['js_frameworks'].append('React')
        if 'angular' in content:
            techs['js_frameworks'].append('Angular')
        if 'vue' in content:
            techs['js_frameworks'].append('Vue.js')
        
        # CDN detection
        if 'cloudflare' in content or headers_lower.get('cf-ray'):
            techs['cdn'].append('Cloudflare')
        if 'akamai' in content:
            techs['cdn'].append('Akamai')
        if 'cloudfront' in headers_lower.get('via', ''):
            techs['cdn'].append('CloudFront')
        
        # Analytics
        if 'google-analytics' in content or 'ga.js' in content:
            techs['analytics'].append('Google Analytics')
        if 'segment' in content:
            techs['analytics'].append('Segment')
        
    except Exception as e:
        pass
    
    return techs

def ai_risk_analysis(domain: str, findings: Dict, api_key: str) -> Dict:
    """Use Claude AI to analyze findings and generate risk score + recommendations"""
    try:
        client = anthropic.Anthropic(api_key=api_key)
    except Exception as e:
        return {'error': f'Invalid API Key: {e}'}
    
    analysis = {
        'risk_score': 0,
        'risk_level': 'UNKNOWN',
        'findings': [],
        'recommendations': [],
        'attack_surface': [],
        'error': None
    }
    
    try:
        prompt = f"""Analyze this domain reconnaissance data and provide security assessment:

Domain: {domain}
DNS Records: {json.dumps(findings.get('dns', {}))}
SSL Certificate: {json.dumps(findings.get('ssl', {}), default=str)}
WHOIS: {json.dumps(findings.get('whois', {}))}
Technologies: {json.dumps(findings.get('tech_stack', {}))}
Subdomains Found: {findings.get('subdomains_count', 0)}

Respond ONLY in this JSON format (no markdown, no extra text):
{{
    "risk_score": <0-100>,
    "risk_level": "<CRITICAL|HIGH|MEDIUM|LOW>",
    "key_findings": [
        "finding1",
        "finding2"
    ],
    "vulnerabilities": [
        {{"tech": "...", "potential_vuln": "...", "severity": "<CRITICAL|HIGH|MEDIUM|LOW>"}},
    ],
    "attack_surface": [
        "attack_path_1",
        "attack_path_2"
    ],
    "recommendations": [
        "recommendation1",
        "recommendation2"
    ],
    "testing_priorities": [
        "test_1",
        "test_2"
    ]
}}"""
        
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        response_text = message.content[0].text.strip()
        # Remove markdown code blocks if present
        if response_text.startswith('```'):
            response_text = response_text.split('```')[1]
            if response_text.startswith('json'):
                response_text = response_text[4:]
        response_text = response_text.strip()
        
        ai_result = json.loads(response_text)
        
        analysis['risk_score'] = ai_result.get('risk_score', 0)
        analysis['risk_level'] = ai_result.get('risk_level', 'UNKNOWN')
        analysis['findings'] = ai_result.get('key_findings', [])
        analysis['vulnerabilities'] = ai_result.get('vulnerabilities', [])
        analysis['attack_surface'] = ai_result.get('attack_surface', [])
        analysis['recommendations'] = ai_result.get('recommendations', [])
        analysis['testing_priorities'] = ai_result.get('testing_priorities', [])
        
    except json.JSONDecodeError as e:
        analysis['error'] = f"Failed to parse AI response: {e}"
    except anthropic.APIError as e:
        analysis['error'] = f"API Error: {e}"
    except Exception as e:
        analysis['error'] = str(e)
    
    return analysis

# ==================== MAIN APP ====================

st.title("🔍 MHZALY Domain Recon Analyzer")
st.markdown("**Bug Bounty + SOC Intelligence Platform** — Map domains, analyze attack surface, prioritize testing")

# Sidebar
with st.sidebar:
    st.header("⚙️ Configuration")
    
    # FIX: Use st.secrets for Streamlit Cloud deployment
    api_key = None
    try:
        api_key = st.secrets.get("ANTHROPIC_API_KEY", "")
    except:
        pass
    
    # Allow manual input as fallback
    manual_api_key = st.text_input("🔑 Anthropic API Key (Optional for AI analysis)", type="password")
    if manual_api_key:
        api_key = manual_api_key
    
    st.markdown("---")
    st.markdown("""
    ### How to Install Tools
```bash
    # Subfinder
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    
    # Python dependencies
    pip install -r requirements.txt
```
    """)

# Main input
col1, col2 = st.columns([3, 1])
with col1:
    domain = st.text_input("🎯 Enter Domain", placeholder="example.com")
with col2:
    analyze_button = st.button("🚀 Analyze", use_container_width=True)

if analyze_button and domain:
    domain = domain.strip().lower().replace('https://', '').replace('http://', '').replace('www.', '')
    
    st.markdown("---")
    
    # Create tabs for organization
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["📊 Overview", "🌐 Infrastructure", "🔐 Security", "🎯 Attack Surface", "📋 Report"])
    
    with st.spinner("🔄 Gathering reconnaissance data..."):
        
        # Collect data
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
        
        # AI Analysis
        ai_analysis = {}
        if api_key:
            ai_analysis = ai_risk_analysis(domain, findings, api_key)
    
    # ==================== TAB 1: OVERVIEW ====================
    with tab1:
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if ai_analysis and 'risk_score' in ai_analysis:
                st.metric("Risk Score", f"{ai_analysis['risk_score']}/100", delta=None)
            else:
                st.metric("Subdomains", findings['subdomains_count'])
        
        with col2:
            if ai_analysis and 'risk_level' in ai_analysis:
                level = ai_analysis['risk_level']
                color_class = f"status-{level.lower()}"
                st.markdown(f"**Risk Level** <br><span class='{color_class}'>{level}</span>", unsafe_allow_html=True)
            else:
                st.metric("DNS Records", len([r for r in findings['dns'].values() if isinstance(r, list) and r]))
        
        with col3:
            tech_count = sum(len(v) if isinstance(v, list) else 0 for v in findings['tech_stack'].values())
            st.metric("Technologies", tech_count)
        
        with col4:
            ssl_valid = "✅ Valid" if findings['ssl'].get('valid') else "❌ Invalid/Missing"
            st.metric("SSL Status", ssl_valid)
        
        st.markdown("---")
        
        if ai_analysis.get('findings'):
            st.subheader("🔴 Key Findings")
            for finding in ai_analysis['findings']:
                st.warning(finding)
    
    # ==================== TAB 2: INFRASTRUCTURE ====================
    with tab2:
        st.subheader("📍 Subdomains Discovered")
        if findings['subdomains']:
            df_subs = pd.DataFrame({'Subdomain': findings['subdomains']})
            st.dataframe(df_subs, use_container_width=True)
            st.download_button(
                "📥 Download Subdomains",
                data='\n'.join(findings['subdomains']),
                file_name=f"{domain}_subdomains.txt"
            )
        else:
            st.info("No subdomains found (subfinder may not be installed)")
        
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
    
    # ==================== TAB 3: SECURITY ====================
    with tab3:
        st.subheader("🔐 SSL Certificate")
        if findings['ssl'].get('valid'):
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Issuer:** {findings['ssl'].get('issuer', 'Unknown')}")
                st.write(f"**Subject:** {findings['ssl'].get('subject', 'Unknown')}")
            with col2:
                st.write(f"**Expiry:** {findings['ssl'].get('expiry', 'Unknown')}")
                st.write(f"**Serial:** {findings['ssl'].get('serial', 'Unknown')}")
        else:
            st.error(f"SSL Error: {findings['ssl'].get('error', 'Unknown error')}")
        
        st.markdown("---")
        st.subheader("🛠 Technologies Detected")
        if findings['tech_stack']:
            for category, techs in findings['tech_stack'].items():
                if techs:
                    st.write(f"**{category.replace('_', ' ').title()}**")
                    for tech in techs:
                        st.badge(tech)
        
        st.markdown("---")
        st.subheader("📋 WHOIS Information")
        if not findings['whois'].get('error'):
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Registrar:** {findings['whois'].get('registrar', 'Unknown')}")
                st.write(f"**Created:** {findings['whois'].get('created', 'Unknown')}")
            with col2:
                st.write(f"**Expires:** {findings['whois'].get('expires', 'Unknown')}")
                st.write(f"**Updated:** {findings['whois'].get('updated', 'Unknown')}")
        else:
            st.warning(f"WHOIS Error: {findings['whois'].get('error')}")
    
    # ==================== TAB 4: ATTACK SURFACE ====================
    with tab4:
        if ai_analysis.get('vulnerabilities'):
            st.subheader("⚠️ Potential Vulnerabilities")
            for vuln in ai_analysis['vulnerabilities']:
                severity = vuln.get('severity', 'MEDIUM').lower()
                with st.container(border=True):
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.write(f"**{vuln.get('tech')}**")
                        st.caption(vuln.get('potential_vuln'))
                    with col2:
                        st.metric("Severity", vuln.get('severity', 'N/A'))
        
        if ai_analysis.get('attack_surface'):
            st.markdown("---")
            st.subheader("🎯 Attack Paths")
            for i, path in enumerate(ai_analysis['attack_surface'], 1):
                st.write(f"{i}. {path}")
        
        if ai_analysis.get('testing_priorities'):
            st.markdown("---")
            st.subheader("🚀 Testing Priorities (For Bug Bounty)")
            for i, test in enumerate(ai_analysis['testing_priorities'], 1):
                st.write(f"**{i}.** {test}")
    
    # ==================== TAB 5: REPORT ====================
    with tab5:
        st.subheader("📊 Executive Summary")
        if ai_analysis:
            if ai_analysis.get('recommendations'):
                st.write("**Recommendations:**")
                for rec in ai_analysis['recommendations']:
                    st.write(f"- {rec}")
        
        # Export options
        st.markdown("---")
        st.subheader("💾 Export")
        
        # JSON export
        json_export = json.dumps({
            **findings,
            'ai_analysis': ai_analysis
        }, indent=2, default=str)
        
        st.download_button(
            "📥 Download Full Report (JSON)",
            data=json_export,
            file_name=f"{domain}_recon_report.json",
            mime="application/json"
        )
        
        # Text export
        text_report = f"""DOMAIN RECONNAISSANCE REPORT
{domain}
Generated: {findings['timestamp']}

RISK LEVEL: {ai_analysis.get('risk_level', 'N/A')} (Score: {ai_analysis.get('risk_score', 'N/A')}/100)

KEY FINDINGS:
{chr(10).join(f"- {f}" for f in ai_analysis.get('findings', []))}

SUBDOMAINS FOUND: {findings['subdomains_count']}

TECHNOLOGIES: {', '.join(str(t) for techs in findings['tech_stack'].values() for t in techs if techs)}

RECOMMENDATIONS:
{chr(10).join(f"- {r}" for r in ai_analysis.get('recommendations', []))}
"""
        
        st.download_button(
            "📥 Download Report (Text)",
            data=text_report,
            file_name=f"{domain}_recon_report.txt"
        )

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #888; font-size: 0.9rem;">
    <p>MHZALY Domain Recon Analyzer | Built for Bug Bounty Hunters & SOC Analysts</p>
    <p>90% Deterministic + 10% AI Intelligence | <a href="https://github.com">Open Source</a></p>
</div>
""", unsafe_allow_html=True)
