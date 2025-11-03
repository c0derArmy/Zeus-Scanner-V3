# Zeus Scanner - Advanced Web Vulnerability Assessment Framework

```
    __          __________                             __   
   / /          \____    /____  __ __  ______          \ \  
  / /    ______   /     // __ \|  |  \/  ___/  ______   \ \ 
  \ \   /_____/  /     /\  ___/|  |  /\___ \  /_____/   / / 
   \_\          /_______ \___  >____//____  >          /_/  
                       \/   \/           \/  v3.0.0
                   Professional Security Testing Platform
                      AI-POWERED • TOOL-INTEGRATED
```

Zeus Scanner is a **next-generation web vulnerability assessment framework** that combines automated reconnaissance with advanced AI analysis and **full integration** with industry-standard penetration testing tools including **OWASP ZAP**, **Burp Suite Professional**, and **Metasploit Framework**.

## NEW: Enhanced Tool Integration

### **Comprehensive AI-Powered Assessment**
```bash
# Complete assessment with all tools and AI orchestration
python3 zeus.py -b https://target.com --comprehensive-assessment

# With active exploitation (use with caution)  
python3 zeus.py -b https://target.com --comprehensive-assessment --enable-exploitation
```


### **AI-Driven Analysis**
- **Autonomous Vulnerability Discovery** - AI finds vulnerabilities other tools miss
- **CVE Detection & Matching** - Real-time CVE database correlation
- **Nuclei Template Generation** - Auto-generates YAML templates from findings
- **Intelligent Risk Assessment** - CVSS 3.1 scoring with contextual analysis
- **Proof-of-Concept Generation** - Creates safe exploitation demonstrations

## Key Features

### Intelligence Gathering & Reconnaissance
- **Advanced Google Dorking**: 1000+ pre-built vulnerability-specific search queries
- **Multi-Engine Search**: Google, Bing, DuckDuckGo, AOL integration
- **Web Crawling**: Blackwidow crawler for comprehensive URL discovery
- **Parameter Detection**: Intelligent GET/POST parameter identification
- **SSL/TLS Assessment**: Certificate analysis and configuration testing

### Vulnerability Detection Engine
- **SQL Injection**: Advanced SQLMap integration supporting 15+ database systems
- **Cross-Site Scripting (XSS)**: 296+ payload vectors with bypass techniques
- **CVE Database Integration**: Real-time CVE detection and matching
- **Admin Panel Discovery**: 500+ common administrative interface paths
- **Clickjacking Detection**: UI redress attack identification
- **File Upload Vulnerabilities**: Unrestricted file upload testing
- **Directory Traversal**: Path traversal vulnerability detection

### Advanced AI-Powered Analysis
- **Autonomous Vulnerability Discovery**: AI-driven vulnerability research
- **Nuclei Template Generation**: Automatic YAML template creation from findings
- **Exploit Chain Analysis**: Multi-stage attack vector identification  
- **Risk Assessment**: Intelligent vulnerability prioritization
- **False Positive Reduction**: Machine learning-based result validation

### Network & Infrastructure Assessment
- **Port Scanning**: Nmap integration for network reconnaissance
- **Service Detection**: Banner grabbing and service identification
- **WHOIS Intelligence**: Domain and IP information gathering
- **Subdomain Enumeration**: Comprehensive subdomain discovery
- **Technology Stack Fingerprinting**: Framework and CMS detection

### Stealth & Evasion Capabilities
- **Proxy Chain Support**: HTTP/HTTPS/SOCKS proxy rotation
- **Tor Network Integration**: Anonymous scanning through Tor
- **User-Agent Spoofing**: 100+ realistic browser fingerprints
- **WAF Detection & Bypass**: Comprehensive firewall identification using wafw00f (120+ WAF signatures)
- **Rate Limiting**: Intelligent request throttling and timing
- **Request Randomization**: Anti-detection traffic patterns

## Installation & Setup

### System Requirements
- **Operating System**: Linux (Kali Linux, Ubuntu, Debian recommended)
- **Python Version**: 3.6 or higher
- **Memory**: Minimum 2GB RAM (4GB+ recommended)
- **Storage**: 1GB+ free disk space
- **Network**: Internet connection for reconnaissance and updates

### Quick Installation
```bash
# Clone or navigate to Zeus Scanner directory
cd /path/to/Zeus-Scanner-V3

# Create and activate virtual environment
python3 -m venv zeus_env
source zeus_env/bin/activate

# Install dependencies
pip3 install -r requirements.txt

# Verify installation
python3 zeus.py --help
```

### System Dependencies
```bash
# Ubuntu/Debian systems
sudo apt update
sudo apt install -y python3 python3-pip python3-venv firefox-esr nmap

# Install wafw00f for WAF detection (required)
sudo apt install -y wafw00f
# OR install from source:
# git clone https://github.com/EnableSecurity/wafw00f.git
# cd wafw00f
# sudo python3 setup.py install

# Install XSSer for XSS testing (required for -x option)
sudo apt install -y xsser
# OR install from source:
# git clone https://github.com/epsylon/xsser.git
# cd xsser
# sudo python3 setup.py install
# Note: XSSer works best with Python 3.12 or earlier

# Install GeckoDriver for Selenium
wget https://github.com/mozilla/geckodriver/releases/latest/download/geckodriver-v0.34.0-linux64.tar.gz
tar -xzf geckodriver-v0.34.0-linux64.tar.gz
sudo mv geckodriver /usr/local/bin/
sudo chmod +x /usr/local/bin/geckodriver

# Optional: Install Tor for anonymous scanning
sudo apt install -y tor

# Optional: Install additional security tools for extended functionality
sudo apt install -y sqlmap nikto nuclei wapiti
```

## Usage Guide

### Basic Command Structure
```
python3 zeus.py [SEARCH_METHOD] [TARGET] [SCAN_MODULES] [OPTIONS]
```

### Search Methods
- `-d "dork query"` - Use specific Google dork for reconnaissance
- `-r` - Use random dork from built-in database
- `-l dorks.txt` - Load dork list from file
- `-b https://target.com` - Spider/crawl target website
- `-f urls.txt` - Test URLs from file

### Scanning Modules
- `-s` - SQL injection vulnerability testing (Sqlmap)
- `-x` - Cross-site scripting (XSS) detection using XSSer (120+ payloads)
- `-p` - Network port scanning (Nmap)
- `-a` - Admin panel discovery
- `-w` - WHOIS domain intelligence
- `-c` - Clickjacking vulnerability assessment
- `--check-waf` - WAF/IDS/IPS detection only (120+ signatures via wafw00f)

### Advanced Tool Arguments
- `--sqlmap-args` - Pass custom arguments to Sqlmap (e.g., `'dbms mysql, level 5'`)
- `--xsser-args` - Pass custom arguments to XSSer (e.g., `'threads 10, Doo, timeout 30'`)
- `--nmap-args` - Pass custom arguments to Nmap (e.g., `'-O|-p 445,1080'`)

### AI-Powered Assessment Options
- `--implement-payloads` - Execute all fetched online payloads against target (ACTIVE TESTING)
- `--comprehensive-payloads` - Test ALL thousands of fetched payloads for maximum coverage
- `--fast-payload-mode` - Fast payload testing mode for quick assessment
- `--exploit-mode` - Enable active exploitation of discovered vulnerabilities
- `--comprehensive-assessment` - Run comprehensive assessment using all available tools and AI

### Example Usage Scenarios

#### Basic Vulnerability Assessment
```bash
# Test a single website comprehensively
python3 zeus.py -b https://example.com -s -x -p -a

# Quick admin panel hunt with SQL injection testing
python3 zeus.py -d "inurl:admin.php" -s -a --batch

# Random target discovery and assessment
python3 zeus.py -r -s -x -p --tor

# Check WAF protection on multiple targets
python3 zeus.py -f targets.txt --check-waf --batch

# XSS testing with custom XSSer arguments
python3 zeus.py -f targets.txt -x --xsser-args "threads 5, Doo, timeout 20" --batch
```

#### AI-Enhanced Security Testing
```bash
# Active payload implementation - implements all online payloads
python3 zeus.py -b https://target.com --implement-payloads

# Comprehensive payload testing - tests ALL thousands of payloads  
python3 zeus.py -b https://target.com --comprehensive-payloads

# Fast payload mode for quick testing
python3 zeus.py -f targets.txt --fast-payload-mode --implement-payloads

# Full tool integration with payload implementation
python3 zeus.py -b https://target.com --comprehensive-assessment --implement-payloads
```

#### Stealth and Evasion Testing
```bash
# Anonymous scanning through Tor with delays
python3 zeus.py -b https://target.com -s -x --tor --time-sec 5

# Proxy rotation with random user agents
python3 zeus.py -d "site:target.com" -s --proxy-file proxies.txt --random-agent

# WAF evasion with tamper scripts
python3 zeus.py -b https://target.com -x --tamper randomcase,space2comment
```

## Advanced Configuration

### Custom Dork Lists
```bash
# Create targeted dork file for specific technologies
echo "inurl:admin.php filetype:php" > custom_dorks.txt
echo "intext:'mysql_connect' filetype:php" >> custom_dorks.txt
echo "site:target.com intitle:'admin panel'" >> custom_dorks.txt

# Execute custom dork scan
python3 zeus.py -l custom_dorks.txt -s -a
```

### Proxy Configuration
```bash
# HTTP proxy with authentication
python3 zeus.py -d "inurl:login" -s --proxy "http://user:pass@proxy:8080"

# SOCKS proxy chain
python3 zeus.py -b https://target.com -s --proxy "socks5://127.0.0.1:9050"

# Multiple proxy rotation
echo "http://proxy1:8080" > proxies.txt
echo "socks5://proxy2:1080" >> proxies.txt
python3 zeus.py -d "admin" -s --proxy-file proxies.txt
```

### SQLMap Integration
```bash
# Advanced SQLMap arguments
python3 zeus.py -d "id=" -s --sqlmap-args "--level=5 --risk=3 --threads=10"

# Custom SQLMap configuration
python3 zeus.py -b https://target.com -s --sqlmap-conf custom_sqlmap.conf

# Tamper script usage for WAF bypass
python3 zeus.py -f targets.txt -s --sqlmap-args "--tamper=space2comment,randomcase"
```

### AI Engine Configuration
```bash
# Comprehensive payload implementation with all online sources
python3 zeus.py -b https://target.com --comprehensive-payloads --implement-payloads

# Fast payload testing for rapid assessment
python3 zeus.py -f targets.txt --fast-payload-mode --implement-payloads

# Tool integration with payload implementation
python3 zeus.py -b https://target.com --use-zap --use-burp --implement-payloads
```

## Results & Reporting

### Output Structure
```
Zeus-Scanner/
├── log/                          # Main logging directory
│   ├── zeus-log-XX.log          # Comprehensive scan logs
│   ├── blackwidow-log/          # Web crawler results
│   ├── url-log/                 # Discovered URLs database
│   └── ai-results/              # AI assessment reports
├── results/                     # Vulnerability findings
│   ├── sql_injection/           # SQLi test results
│   ├── xss_findings/           # XSS vulnerability reports
│   ├── cve_reports/            # CVE detection results
│   └── nuclei_templates/       # Generated Nuclei templates
└── exports/                    # Report exports
    ├── json/                   # JSON format reports
    ├── xml/                    # XML format reports  
    └── html/                   # HTML vulnerability reports
```

### Analyzing Results
```bash
# View latest scan results
tail -f log/zeus-log-$(ls log/ | grep zeus-log | tail -1)

# Extract discovered URLs
grep -E "https?://" log/url-log/url-log-*.log | sort -u

# Parse vulnerability findings
python3 tools/parse_results.py log/zeus-log-1.log --format json

# Generate comprehensive report
python3 tools/generate_report.py --input log/ --output vulnerability_report.html
```

### Export Formats
```bash
# JSON export for integration
python3 zeus.py -b https://target.com -s -x --export-json results.json

# XML export for other tools
python3 zeus.py -f targets.txt --cve-scan --export-xml cve_findings.xml

# CSV export for analysis
python3 tools/export_csv.py log/zeus-log-1.log > scan_results.csv
```

## Performance & Optimization

### Scanning Statistics
| Component | Performance Metric |
|-----------|-------------------|
| **URL Discovery** | 50-500 URLs/minute |
| **XSS Testing** | 10-100 payloads/second |
| **SQL Injection** | 5-25 requests/second |
| **Port Scanning** | 1000+ ports/minute |
| **CVE Detection** | 100+ CVEs/minute |
| **AI Analysis** | Real-time processing |

### Resource Management
```bash
# Limit concurrent operations
python3 zeus.py -d "target" -s --threads 5 --time-sec 2

# Memory-efficient scanning
python3 zeus.py -b https://target.com -s --batch --minimal-output

# Bandwidth optimization
python3 zeus.py -f large_targets.txt -s --crawl-delay 1 --proxy-rotation
```

### Performance Tuning
```bash
# High-speed scanning (use with caution)
python3 zeus.py -b https://target.com -s -x --threads 20 --time-sec 0.1

# Stealth mode (slow but evasive)
python3 zeus.py -d "target" -s --tor --time-sec 10 --random-agent

# Balanced performance
python3 zeus.py -f targets.txt -s -x --threads 10 --time-sec 1
```

## Vulnerability Testing Scenarios

### Educational Testing Environments
Practice ethical hacking skills on these intentionally vulnerable applications:

**Web Application Testing Labs:**
- **testphp.vulnweb.com** - Acunetix PHP testing environment
- **demo.testfire.net** - IBM Security AppScan demonstration site
- **dvwa.co.uk** - Damn Vulnerable Web Application
- **bwapp.hakhub.net** - Buggy Web Application project
- **mutillidae.sourceforge.net** - OWASP Mutillidae II

### Real-World Testing Scenarios

#### Corporate Network Assessment
```bash
# Phase 1: Reconnaissance and intelligence gathering
python3 zeus.py -d "site:corporation.com filetype:pdf OR filetype:doc" -w

# Phase 2: Admin interface discovery
python3 zeus.py -d "site:corporation.com inurl:admin OR inurl:login" -a -s

# Phase 3: Comprehensive vulnerability assessment and payload implementation
python3 zeus.py -f discovered_targets.txt --comprehensive-payloads --implement-payloads
```

#### E-commerce Platform Security Audit
```bash
# Infrastructure mapping
python3 zeus.py -b https://shop.example.com -p --crawl-delay 2

# Payment system analysis
python3 zeus.py -d "site:shop.example.com inurl:checkout OR inurl:payment" -s -x

# Customer data exposure testing
python3 zeus.py -d "site:shop.example.com filetype:sql OR filetype:db" -s
```

#### Educational Institution Assessment
```bash
# Student portal vulnerability research
python3 zeus.py -d "site:university.edu inurl:student OR inurl:portal" -a -s -x

# Faculty and admin system testing with payload implementation
python3 zeus.py -d "site:university.edu inurl:faculty OR inurl:staff" --implement-payloads

# Research data exposure analysis
python3 zeus.py -d "site:university.edu filetype:xlsx OR filetype:csv" -w
```

### AI-Enhanced Testing Workflows

#### Autonomous Vulnerability Discovery
```bash
# Comprehensive payload implementation from all online sources
python3 zeus.py -b https://target.com --comprehensive-payloads --implement-payloads

# Advanced exploitation with payload implementation
python3 zeus.py -f complex_app_urls.txt --implement-payloads --exploit-mode

# Fast payload assessment for rapid testing
python3 zeus.py -b https://target.com --fast-payload-mode --implement-payloads
```

#### CVE Research and Payload Implementation
```bash
# Comprehensive payload testing with vulnerability detection
python3 zeus.py -b https://target.com --comprehensive-payloads --verbose

# Active payload implementation with comprehensive coverage
python3 zeus.py -f targets.txt --implement-payloads --comprehensive-payloads

# Fast payload implementation for quick assessment
python3 zeus.py -b https://target.com --fast-payload-mode --implement-payloads
```

## Security Best Practices

### Ethical Guidelines
**CRITICAL WARNING**: Zeus Scanner is designed exclusively for authorized security testing. Misuse of this tool may violate local, national, and international laws.

### Authorized Usage
- **Personal Projects**: Testing your own applications and infrastructure
- **Professional Engagements**: Authorized penetration testing with written consent
- **Educational Purposes**: Learning on designated vulnerable applications
- **Research Activities**: Security research in controlled environments
- **Bug Bounty Programs**: Testing within program scope and rules

### Legal Compliance Checklist
```
[ ] Written authorization obtained from target owner
[ ] Testing scope clearly defined and documented  
[ ] Backup and rollback procedures established
[ ] Non-disclosure agreements signed if required
[ ] Local and international laws researched and complied with
[ ] Emergency contacts established for incident response
```

### Responsible Disclosure Process
1. **Discovery Phase**: Identify vulnerability without exploitation
2. **Documentation**: Create detailed proof-of-concept without causing damage
3. **Initial Contact**: Reach out to organization through proper channels
4. **Coordinated Timeline**: Allow reasonable time for remediation (90-120 days)
5. **Public Disclosure**: Follow coordinated disclosure best practices

### Operational Security
```bash
# Use VPN and Tor for additional anonymity
python3 zeus.py -b https://target.com --tor --proxy-chain

# Implement proper logging and audit trails
python3 zeus.py -f targets.txt -s -x --detailed-logging --audit-mode

# Use throwaway infrastructure for testing
python3 zeus.py --cloud-scanner --disposable-resources
```

## Troubleshooting & FAQ

### Common Issues and Solutions

#### SSL Certificate Verification Errors
```bash
# Disable SSL verification (use with caution)
python3 zeus.py -b https://target.com -s --disable-ssl-verification

# Use custom SSL context
python3 zeus.py -b https://target.com -s --ssl-context custom_ssl.conf
```

#### Proxy Connection Problems
```bash
# Test proxy connectivity
python3 tools/test_proxy.py --proxy socks5://127.0.0.1:9050

# Auto-rotate failed proxies
python3 zeus.py -f targets.txt -s --proxy-file proxies.txt --auto-rotate-proxy
```

#### Memory and Performance Issues
```bash
# Memory-efficient scanning for large target lists
python3 zeus.py -f large_targets.txt -s --memory-efficient --batch-size 50

# CPU usage optimization
python3 zeus.py -b https://target.com -s -x --cpu-limit 50 --nice-priority 10
```

### Debugging Mode
```bash
# Enable verbose debugging output
python3 zeus.py -b https://target.com -s -x --debug --verbose

# Generate detailed error reports
python3 zeus.py --error-reporting --send-crash-reports
```

## Integration & API

### Third-Party Tool Integration
```bash
# Export results to Metasploit
python3 zeus.py -f targets.txt -s --export-msf workspace_file.rc

# Integration with OWASP ZAP
python3 zeus.py -b https://target.com --zap-integration --zap-api-key KEY

# Burp Suite integration
python3 zeus.py -f urls.txt -s --burp-integration --burp-api http://localhost:8080
```

### Custom Plugin Development
```python
# Example custom vulnerability detector plugin
from lib.core.plugin_base import VulnPlugin

class CustomVulnDetector(VulnPlugin):
    def __init__(self):
        self.name = "Custom Vulnerability Detector"
        self.description = "Detects custom application vulnerabilities"
    
    def scan(self, target_url, **kwargs):
        # Implement custom vulnerability detection logic
        return vulnerability_findings
```

### API Endpoints
```bash
# Start Zeus Scanner REST API server
python3 api_server.py --host 0.0.0.0 --port 8888

# REST API usage examples
curl -X POST http://localhost:8888/scan -d '{"target": "https://example.com", "modules": ["sqli", "xss"]}'
curl -X GET http://localhost:8888/results/scan_id_12345
```
