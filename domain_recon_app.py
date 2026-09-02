import streamlit as st
import subprocess
import json
import socket
import ssl
import requests
from datetime import datetime
from typing import Dict, List
import pandas as pd
import google.generativeai as genai
import urllib3
import os

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
                    try:
                        cert_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    except:
                        cert_info['issuer'] = "N/A"
                    
                    try:
                        cert_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                    except:
                        cert_info['subject'] = "N/A"
                    
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
        whois_data['registrar'] = str(w.registrar) if hasattr(w, 'registrar') else "N/A"
        whois_data['created'] = str(w.creation_date)[:10] if hasattr(w, 'creation_date') else None
        whois_data['expires'] = str(w.expiration_date)[:10] if hasattr(w, 'expiration_date') else None
        whois_data['updated'] = str(w.updated_date)[:10] if hasattr(w, 'updated_date') else None
        whois_data['status'] = str(w.status)[0] if hasattr(w, 'status') else None
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
        if result.returncode == 0 and result.stdout.strip():
            return [s for s in result.stdout.strip().split('\n') if s]
        else:
            return []
    except FileNotFoundError:
        return []
    except Exception:
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
        
        # Server detection
        if 'server' in headers_lower:
            server = headers_lower['server']
            if server not in techs['web_servers']:
                techs['web_servers'].append(server)
        
        # CMS detection
        if 'wordpress' in content or 'wp-content' in content:
            techs['cms'].append('WordPress')
        if 'drupal' in content:
            techs['cms'].append('Drupal')
        if 'joomla' in content:
            techs['cms'].append('Joomla')
        
        # JS Framework detection
        if 'react' in content or '"react"' in content:
            techs['js_frameworks'].append('React')
        if 'angular' in content:
            techs['js_frameworks'].append('Angular')
        if 'vue' in content or 'vue.js' in content:
            techs['js_frameworks'].append('Vue.js')
        
        # CDN detection
        if 'cloudflare' in content or 'cf-ray' in headers_lower:
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
        
    except Exception:
        pass
    
    return techs

def ai_risk_analysis(domain: str, findings: Dict, api_key: str) -> Dict:
    """Use Google Gemini API to analyze findings"""
    analysis = {
        'risk_score': 50,
        'risk_level': 'MEDIUM',
        'findings': [],
        'recommendations': [],
        'vulnerabilities': [],
        'attack_surface': [],
        'error': None
    }
    
    if not api_key:
        analysis['error'] = "No API key provided"
        return analysis
    
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-pro')
        
        # Clean data for prompt
        dns_summary = f"A: {len(findings['dns'].get('A', []))}, MX: {len(findings['dns'].get('MX', []))}, NS: {len(findings['dns'].get('NS', []))}"
        ssl_status = "Valid" if findings['ssl'].get('valid') else "Invalid/Missing"
        tech_list = []
        for category, items in findings['tech_stack'].items():
            if items:
                tech_list.extend(items)
        
        prompt = f"""Analyze this domain security and respond ONLY with VALID JSON:

Domain: {domain}
DNS: {dns_summary}
SSL: {ssl_status}
Technologies: {', '.join(tech_list) if tech_list else 'None detected'}
Subdomains found: {findings['subdomains_count']}

IMPORTANT: Your response must be ONLY valid JSON, no markdown formatting, no extra text.

{{
    "risk_score": <integer 0-100>,
    "risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
    "findings": ["finding1", "finding2"],
    "vulnerabilities": ["vuln1", "vuln2"],
    "recommendations": ["recommendation1"],
    "attack_surface": ["attack1"]
}}"""
        
        response = model.generate_content(prompt, safety_settings=[])
        response_text = response.text.strip()
        
        # Clean response
        if '```' in response_text:
            response_text = response_text.split('```')[1]
            if response_text.startswith('json'):
                response_text = response_text[4:]
        
        response_text = response_text.strip()
        
        # Parse JSON
        ai_result = json.loads(response_text)
        
        analysis['risk_score'] = min(100, max(0, ai_result.get('risk_score', 50)))
        analysis['risk_level'] = ai_result.get('risk_level', 'MEDIUM')
        analysis['findings'] = ai_result.get('findings', [])[:5]
        analysis['vulnerabilities'] = ai_result.get('vulnerabilities', [])[:5]
        analysis['recommendations'] = ai_result.get('recommendations', [])[:5]
        analysis['attack_surface'] = ai_result.get('attack_surface', [])[:5]
        
    except json.JSONDecodeError as e:
        analysis['error'] = f"JSON parsing error: {str(e)}"
    except Exception as e:
        analysis['error'] = f"API Error: {str(e)}"
    
    return analysis

# ==================== MAIN APP ====================

st.title("🔍 MHZALY Domain Recon Analyzer")
st.markdown("**Bug Bounty + SOC Intelligence Platform** — Powered by Google Gemini AI")

# Sidebar
with st.sidebar:
    st.header("⚙️ Configuration")
    
    # Try to get API key from secrets
    api_key = ""
    try:
        api_key = st.secrets.get("GEMINI_API_KEY", "")
    except:
        pass
    
    # Get from user input if not in secrets
    if not api_key:
        api_key = st.text_input("🔑 Google Gemini API Key", type="password", placeholder="sk-...")
    else:
        st.success("✅ API Key loaded from secrets")
    
    st.markdown("---")
    st.markdown("""
    ### Get Free API Key
    1. Go to [Google AI Studio](https://ai.google.dev)
    2. Sign in with Google account
    3. Create new API key
    4. Copy and paste here
    
    **Free Tier:** 60 requests/minute
    """)
    
    st.markdown("---")
    
    if st.checkbox("ℹ️ Show tool info"):
        st.info("""
        **What this tool does:**
        - Maps domain infrastructure
        - Detects technologies
        - Analyzes security posture
        - Recommends testing priorities
        
        **Perfect for:**
        - Bug bounty hunting
        - SOC analysis
        - Security assessment
        """)

# Main input
col1, col2 = st.columns([3, 1])
with col1:
    domain = st.text_input("🎯 Enter Domain", placeholder="example.com")
with col2:
    analyze_button = st.button("🚀 Analyze", use_container_width=True)

if analyze_button and domain:
    domain = domain.strip().lower()
    domain = domain.replace('https://', '').replace('http://', '').replace('www.', '')
    
    if not domain:
        st.error("❌ Please enter a valid domain")
    else:
        st.markdown("---")
        
        tab1, tab2, tab3, tab4, tab5 = st.tabs(["📊 Overview", "🌐 Infrastructure", "🔐 Security", "🎯 Analysis", "📋 Report"])
        
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
            
            findings['subdomains_count'] = len([s for s in findings['subdomains'] if s])
            
            ai_analysis = {}
            if api_key:
                with st.spinner("🤖 AI Analysis (Gemini)..."):
                    ai_analysis = ai_risk_analysis(domain, findings, api_key)
            else:
                st.warning("⚠️ No API key - skipping AI analysis")
        
        # ========== TAB 1: OVERVIEW ==========
        with tab1:
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                if ai_analysis and ai_analysis.get('risk_score'):
                    st.metric("🎯 Risk Score", f"{ai_analysis['risk_score']}/100")
                else:
                    st.metric("🎯 Subdomains", findings['subdomains_count'])
            
            with col2:
                if ai_analysis and ai_analysis.get('risk_level'):
                    level = ai_analysis['risk_level']
                    color = "🔴" if level == "CRITICAL" else "🟠" if level == "HIGH" else "🟡" if level == "MEDIUM" else "🟢"
                    st.metric("⚠️ Risk Level", f"{color} {level}")
                else:
                    dns_count = sum(1 for k, v in findings['dns'].items() if k != 'error' and v)
                    st.metric("⚠️ DNS Records", dns_count)
            
            with col3:
                tech_count = sum(len(v) if isinstance(v, list) else 0 for v in findings['tech_stack'].values())
                st.metric("🛠️ Technologies", tech_count)
            
            with col4:
                ssl_icon = "✅" if findings['ssl'].get('valid') else "❌"
                st.metric("🔒 SSL Status", ssl_icon)
            
            st.markdown("---")
            
            if ai_analysis and ai_analysis.get('findings'):
                st.subheader("🔴 Key Findings")
                for finding in ai_analysis['findings']:
                    st.warning(f"⚠️ {finding}")
            
            if ai_analysis and ai_analysis.get('error'):
                st.error(f"Analysis Error: {ai_analysis['error']}")
        
        # ========== TAB 2: INFRASTRUCTURE ==========
        with tab2:
            st.subheader("📍 Subdomains Discovered")
            subdomains_clean = [s for s in findings['subdomains'] if s]
            if subdomains_clean:
                st.success(f"✅ Found {len(subdomains_clean)} subdomains")
                df = pd.DataFrame({'Subdomain': subdomains_clean})
                st.dataframe(df, use_container_width=True)
                
                st.download_button(
                    "📥 Download Subdomains",
                    data='\n'.join(subdomains_clean),
                    file_name=f"{domain}_subdomains.txt"
                )
            else:
                st.info("ℹ️ No subdomains found (install subfinder for better results)")
            
            st.markdown("---")
            st.subheader("🌐 DNS Records")
            dns_cols = st.columns(3)
            
            with dns_cols[0]:
                a_records = findings['dns'].get('A', [])
                if a_records:
                    st.write("**A Records**")
                    for record in a_records:
                        st.code(record, language="text")
            
            with dns_cols[1]:
                mx_records = findings['dns'].get('MX', [])
                if mx_records:
                    st.write("**MX Records**")
                    for record in mx_records:
                        st.code(record, language="text")
            
            with dns_cols[2]:
                ns_records = findings['dns'].get('NS', [])
                if ns_records:
                    st.write("**NS Records**")
                    for record in ns_records:
                        st.code(record, language="text")
        
        # ========== TAB 3: SECURITY ==========
        with tab3:
            st.subheader("🔐 SSL Certificate")
            if findings['ssl'].get('valid'):
                st.success("✅ Valid SSL Certificate")
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Issuer:** {findings['ssl'].get('issuer', 'N/A')}")
                    st.write(f"**Subject:** {findings['ssl'].get('subject', 'N/A')}")
                with col2:
                    st.write(f"**Expiry:** {findings['ssl'].get('expiry', 'N/A')}")
                    st.write(f"**Serial:** {findings['ssl'].get('serial', 'N/A')}")
            else:
                st.error(f"❌ SSL Error: {findings['ssl'].get('error', 'Unknown')}")
            
            st.markdown("---")
            st.subheader("🛠 Technologies Detected")
            if findings['tech_stack']:
                tech_found = False
                for category, techs in findings['tech_stack'].items():
                    if techs:
                        tech_found = True
                        st.write(f"**{category.replace('_', ' ').title()}:** {', '.join(techs)}")
                if not tech_found:
                    st.info("No specific technologies detected")
            else:
                st.info("No technologies detected")
            
            st.markdown("---")
            st.subheader("📋 WHOIS Information")
            if not findings['whois'].get('error'):
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Registrar:** {findings['whois'].get('registrar', 'N/A')}")
                    st.write(f"**Created:** {findings['whois'].get('created', 'N/A')}")
                with col2:
                    st.write(f"**Expires:** {findings['whois'].get('expires', 'N/A')}")
                    st.write(f"**Updated:** {findings['whois'].get('updated', 'N/A')}")
            else:
                st.warning(f"⚠️ WHOIS Error: {findings['whois'].get('error')}")
        
        # ========== TAB 4: AI ANALYSIS ==========
        with tab4:
            if ai_analysis and not ai_analysis.get('error'):
                if ai_analysis.get('vulnerabilities'):
                    st.subheader("⚠️ Potential Vulnerabilities")
                    for i, vuln in enumerate(ai_analysis['vulnerabilities'], 1):
                        st.warning(f"**{i}.** {vuln}")
                
                if ai_analysis.get('attack_surface'):
                    st.markdown("---")
                    st.subheader("🎯 Attack Surface")
                    for i, attack in enumerate(ai_analysis['attack_surface'], 1):
                        st.info(f"**{i}.** {attack}")
            else:
                st.warning("AI analysis not available")
        
        # ========== TAB 5: REPORT ==========
        with tab5:
            st.subheader("📊 Summary Report")
            
            if ai_analysis and ai_analysis.get('recommendations'):
                st.write("**Recommendations:**")
                for rec in ai_analysis['recommendations']:
                    st.write(f"✓ {rec}")
            
            st.markdown("---")
            st.subheader("💾 Export Report")
            
            # JSON export
            json_data = {
                'domain': findings['domain'],
                'timestamp': findings['timestamp'],
                'subdomains_count': findings['subdomains_count'],
                'ssl': findings['ssl'],
                'whois': findings['whois'],
                'tech_stack': findings['tech_stack'],
                'ai_analysis': ai_analysis
            }
            
            json_export = json.dumps(json_data, indent=2, default=str)
            st.download_button(
                "📥 Download JSON Report",
                data=json_export,
                file_name=f"{domain}_recon_report.json",
                mime="application/json"
            )
            
            # Text export
            text_report = f"""DOMAIN RECONNAISSANCE REPORT
{'='*50}
Domain: {domain}
Timestamp: {findings['timestamp']}

RISK ASSESSMENT
{'='*50}
Risk Score: {ai_analysis.get('risk_score', 'N/A')}/100
Risk Level: {ai_analysis.get('risk_level', 'N/A')}

INFRASTRUCTURE
{'='*50}
Subdomains Found: {findings['subdomains_count']}
Technologies: {sum(len(v) if isinstance(v, list) else 0 for v in findings['tech_stack'].values())}
SSL Status: {'Valid' if findings['ssl'].get('valid') else 'Invalid'}

FINDINGS & RECOMMENDATIONS
{'='*50}
{chr(10).join(f"• {f}" for f in ai_analysis.get('findings', []))}

RECOMMENDATIONS
{'='*50}
{chr(10).join(f"• {r}" for r in ai_analysis.get('recommendations', []))}
"""
            
            st.download_button(
                "📥 Download Text Report",
                data=text_report,
                file_name=f"{domain}_recon_report.txt"
            )

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #888; font-size: 0.9rem;">
    <p>🔍 MHZALY Domain Recon Analyzer | Powered by Google Gemini AI</p>
    <p>90% Deterministic + 10% AI Intelligence | Bug Bounty & Security Intelligence</p>
    <p><a href="https://github.com/Iamhasaanzahid/mhzaly-domain-recon">GitHub</a></p>
</div>
""", unsafe_allow_html=True)
