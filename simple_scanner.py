#!/usr/bin/env python3

import argparse
import requests
import time
import re
import uuid
import os
import markdown2
import json
import base64
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from http.cookies import SimpleCookie

RATE_LIMIT = 0.8  # seconds between requests

COMMON_PATHS = [
    ".git/", ".git/config", "backup/", "admin/", "uploads/", "config.php", "wp-login.php",
    "robots.txt", "sitemap.xml", ".env", "phpinfo.php", ".htaccess", "web.config",
    "database.sql", "dump.sql", "backup.zip", "config.json", "settings.php",
    "test/", "tmp/", "temp/", "logs/", "log/", "admin.php", "login.php"
]

# XSS payloads for different contexts
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "<img src=x onerror=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<svg onload=alert('XSS')>",
    "';alert('XSS');//",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>"
]

# SQL injection payloads
SQL_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT 1,2,3 --",
    "admin'--",
    "' OR 1=1#",
    "1' OR '1'='1' --",
    "' WAITFOR DELAY '00:00:05' --",
    "'; EXEC xp_cmdshell('dir'); --"
]

SQL_ERRORS = [
    r"SQL syntax", r"mysql_fetch", r"ORA-\d+", r"PostgreSQL.*ERROR",
    r"You have an error in your SQL syntax", r"syntax error at or near",
    r"OLE DB.*error", r"Microsoft.*ODBC.*error", r"SQLServer JDBC Driver",
    r"Oracle.*error", r"MySQL.*error", r"Warning.*mysql_.*", r"valid MySQL result",
    r"PostgreSQL.*query failed", r"Warning.*pg_.*", r"valid PostgreSQL result"
]

HEADERS_TO_CHECK = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
    "X-XSS-Protection", "Permissions-Policy", "Cross-Origin-Embedder-Policy"
]

def norm(url):
    if not url.startswith("http"):
        url = "http://" + url
    return url.rstrip("/")

def same_host(base, link):
    return urlparse(base).netloc == urlparse(link).netloc

def fetch(url, session, allow_redirects=True, data=None, method="GET"):
    try:
        if method.upper() == "POST":
            r = session.post(url, data=data, timeout=10, allow_redirects=allow_redirects)
        else:
            r = session.get(url, params=data, timeout=10, allow_redirects=allow_redirects)
        time.sleep(RATE_LIMIT)
        return r
    except Exception as e:
        print(f"[!] fetch error {url}: {e}")
        return None

def gather_links(html, base):
    soup = BeautifulSoup(html, "lxml")
    links = set()
    for a in soup.find_all("a", href=True):
        links.add(urljoin(base, a["href"]))
    return links

def find_forms(html, base):
    soup = BeautifulSoup(html, "lxml")
    forms = []
    tokens = []
    for f in soup.find_all("form"):
        action = f.get("action") or base
        method = (f.get("method") or "get").lower()
        inputs = []
        for i in f.find_all(["input", "textarea", "select"]):
            input_data = {
                "name": i.get("name"), 
                "type": i.get("type", "text"), 
                "value": i.get("value", "")
            }
            if input_data["type"] == "hidden":
                input_data["hidden"] = True
                if input_data["name"] and any(token in input_data["name"].lower() for token in ["token", "csrf", "_token", "nonce"]):
                    tokens.append(input_data["name"])
            inputs.append(input_data)
        forms.append({"action": urljoin(base, action), "method": method, "inputs": inputs})
    
    #  JavaScript token detection
    scripts = soup.find_all("script")
    for s in scripts:
        if s.string:
            # Look for various token patterns in JavaScript
            token_patterns = [
                r"token['\"]\s*[:=]\s*['\"][\w-]+['\"]",
                r"csrf['\"]\s*[:=]\s*['\"][\w-]+['\"]",
                r"_token['\"]\s*[:=]\s*['\"][\w-]+['\"]",
                r"authenticity_token['\"]\s*[:=]\s*['\"][\w-]+['\"]"
            ]
            for pattern in token_patterns:
                if re.search(pattern, s.string, re.I):
                    tokens.append("JS-based token detected")
                    break
    
    return forms, list(set(tokens))

def check_headers(resp):
    missing = []
    weak = []
    
    for h in HEADERS_TO_CHECK:
        if h not in resp.headers:
            risk = "High" if h in ["Content-Security-Policy", "Strict-Transport-Security"] else "Medium"
            missing.append({"header": h, "risk": risk, "issue": "Missing"})
        else:
            # Check for weak configurations
            header_value = resp.headers[h].lower()
            if h == "X-Frame-Options" and header_value not in ["deny", "sameorigin"]:
                weak.append({"header": h, "value": resp.headers[h], "risk": "Medium", "issue": "Weak configuration"})
            elif h == "Content-Security-Policy" and "unsafe-inline" in header_value:
                weak.append({"header": h, "value": resp.headers[h], "risk": "Medium", "issue": "unsafe-inline detected"})
            elif h == "Strict-Transport-Security" and "max-age" not in header_value:
                weak.append({"header": h, "value": resp.headers[h], "risk": "Medium", "issue": "Missing max-age"})
    
    cookies = check_cookies(resp)
    return {
        "missing_headers": missing, 
        "weak_headers": weak,
        "server": resp.headers.get("Server"), 
        "cookies": cookies,
        "powered_by": resp.headers.get("X-Powered-By")
    }

def check_cookies(resp):
    vulnerabilities = []
    
    # Parse Set-Cookie headers properly
    set_cookie_headers = resp.headers.get_list('Set-Cookie') if hasattr(resp.headers, 'get_list') else [resp.headers.get('Set-Cookie', '')]
    
    for cookie_header in set_cookie_headers:
        if not cookie_header:
            continue
            
        # Parse cookie attributes
        cookie_parts = cookie_header.split(';')
        cookie_name = cookie_parts[0].split('=')[0].strip() if cookie_parts else 'unknown'
        
        flags = [part.strip().lower() for part in cookie_parts[1:]]
        
        # Check for missing security flags
        if not any('httponly' in flag for flag in flags):
            vulnerabilities.append({
                "name": cookie_name, 
                "issue": "Missing HttpOnly flag", 
                "risk": "Medium",
                "description": "Cookie accessible via JavaScript"
            })
        
        if resp.url.startswith('https') and not any('secure' in flag for flag in flags):
            vulnerabilities.append({
                "name": cookie_name, 
                "issue": "Missing Secure flag", 
                "risk": "Medium",
                "description": "Cookie can be sent over HTTP"
            })
        
        if not any('samesite' in flag for flag in flags):
            vulnerabilities.append({
                "name": cookie_name, 
                "issue": "Missing SameSite attribute", 
                "risk": "Low",
                "description": "Vulnerable to CSRF attacks"
            })
    
    return vulnerabilities

def check_common_paths(base, session):
    found = []
    for p in COMMON_PATHS:
        url = base + "/" + p if not base.endswith("/") else base + p
        r = fetch(url, session)
        if r and r.status_code in (200, 403, 301, 302):
            if r.status_code == 200:
                risk = "High" if any(ext in p for ext in ['.env', '.git', 'config', 'backup']) else "Medium"
            else:
                risk = "Low"
            found.append({
                "path": url, 
                "code": r.status_code, 
                "risk": risk,
                "size": len(r.content) if r.content else 0
            })
    return found

def test_xss_comprehensive(url, session, params=None, method="get"):
    """Comprehensive XSS testing with multiple payloads and contexts."""
    results = []
    
    for payload in XSS_PAYLOADS:
        marker = f"XSS_TEST_{uuid.uuid4().hex[:8]}"
        test_payload = payload.replace("'XSS'", f"'{marker}'").replace('"XSS"', f'"{marker}"')
        
        data = params.copy() if params else {}
        if not data:
            data = {"q": test_payload}
        else:
            # Test each parameter individually
            for param_name in data.keys():
                test_data = data.copy()
                test_data[param_name] = test_payload
                
                try:
                    r = fetch(url, session, data=test_data, method=method)
                    if r and marker in r.text:
                        # Check context of reflection
                        context = "Unknown"
                        if f'<script>' in r.text or f'javascript:' in r.text:
                            context = "JavaScript"
                        elif f'<' in test_payload and f'>' in test_payload and test_payload in r.text:
                            context = "HTML"
                        elif f'onerror=' in r.text or f'onload=' in r.text:
                            context = "HTML Attribute"
                        
                        results.append({
                            "url": r.url,
                            "parameter": param_name,
                            "payload": test_payload,
                            "marker": marker,
                            "context": context,
                            "risk": "High",
                            "type": "Reflected XSS"
                        })
                except Exception as e:
                    print(f"XSS test error: {e}")
                    continue
    
    return results

def test_sql_injection_comprehensive(url, session, params=None, method="get"):
    """Comprehensive SQL injection testing."""
    results = []
    
    for payload in SQL_PAYLOADS:
        data = params.copy() if params else {}
        if not data:
            data = {"id": payload}
        else:
            # Test each parameter individually
            for param_name in data.keys():
                test_data = data.copy()
                original_value = test_data[param_name]
                test_data[param_name] = str(original_value) + payload
                
                try:
                    start_time = time.time()
                    r = fetch(url, session, data=test_data, method=method)
                    response_time = time.time() - start_time
                    
                    if r:
                        # Check for SQL errors
                        for pattern in SQL_ERRORS:
                            if re.search(pattern, r.text, re.I):
                                results.append({
                                    "url": r.url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "error_pattern": pattern,
                                    "risk": "High",
                                    "type": "SQL Injection (Error-based)"
                                })
                                break
                        
                        # Time-based detection (basic)
                        if "WAITFOR DELAY" in payload and response_time > 5:
                            results.append({
                                "url": r.url,
                                "parameter": param_name,
                                "payload": payload,
                                "response_time": response_time,
                                "risk": "High",
                                "type": "SQL Injection (Time-based)"
                            })
                        
                        # Check for boolean-based patterns (different content length/structure)
                        if "OR '1'='1" in payload:
                            # Test with false condition
                            false_data = test_data.copy()
                            false_data[param_name] = str(original_value) + "' AND '1'='0"
                            r_false = fetch(url, session, data=false_data, method=method)
                            
                            if r_false and len(r.text) != len(r_false.text):
                                results.append({
                                    "url": r.url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "risk": "High",
                                    "type": "SQL Injection (Boolean-based)"
                                })
                
                except Exception as e:
                    print(f"SQL injection test error: {e}")
                    continue
    
    return results

def test_parameter_pollution(url, session, params=None, method="get"):
    """Test for HTTP Parameter Pollution vulnerabilities."""
    results = []
    
    if not params:
        return results
    
    for param_name in params.keys():
        # Test parameter pollution by duplicating parameters
        pollution_data = params.copy()
        pollution_data[param_name] = [params[param_name], "polluted_value"]
        
        try:
            r = fetch(url, session, data=pollution_data, method=method)
            if r and "polluted_value" in r.text:
                results.append({
                    "url": r.url,
                    "parameter": param_name,
                    "risk": "Medium",
                    "type": "HTTP Parameter Pollution",
                    "description": "Application may be vulnerable to parameter pollution attacks"
                })
        except Exception as e:
            continue
    
    return results

def check_directory_traversal(base, session):
    """Test for directory traversal vulnerabilities."""
    results = []
    traversal_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    ]
    
    # Test common parameters that might be vulnerable
    test_params = ["file", "page", "include", "path", "doc", "document"]
    
    for param in test_params:
        for payload in traversal_payloads:
            test_url = f"{base}/?{param}={payload}"
            try:
                r = fetch(test_url, session)
                if r and (re.search(r"root:.*:/bin/", r.text) or 
                         re.search(r"# Copyright.*Microsoft Corp", r.text)):
                    results.append({
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "risk": "High",
                        "type": "Directory Traversal",
                        "description": "Sensitive file content detected in response"
                    })
            except Exception as e:
                continue
    
    return results

def analyze_target(start_url, max_pages=30):
    session = requests.Session()
    session.headers.update({"User-Agent": "ScannerLearning/2.0"})
    base = norm(start_url)
    to_visit = {base}
    visited = set()
    findings = {
        "pages": [], 
        "open_paths": [], 
        "headers": {}, 
        "forms": [], 
        "xss_vulnerabilities": [],
        "sql_vulnerabilities": [],
        "parameter_pollution": [],
        "directory_traversal": [],
        "tokens": [],
        "software_stack": {}
    }

    print(f"[*] Starting comprehensive scan of {base}")
    
    while to_visit and len(visited) < max_pages:
        url = to_visit.pop()
        if url in visited: 
            continue
        if not same_host(base, url): 
            continue
        
        print(f"[*] Scanning: {url}")
        r = fetch(url, session)
        visited.add(url)
        
        if not r: 
            continue
            
        findings["pages"].append({"url": url, "status": r.status_code, "size": len(r.content)})
        
        # Headers/cookies check for the base page
        if url == base:
            findings["headers"] = check_headers(r)
            # Extract software stack information
            findings["software_stack"] = {
                "server": r.headers.get("Server", "Unknown"),
                "powered_by": r.headers.get("X-Powered-By", "Unknown"),
                "framework": extract_framework_info(r)
            }
        
        # Gather links
        links = gather_links(r.text, url)
        for link in links:
            if same_host(base, link) and link not in visited:
                clean_link = link.split("#")[0].split("?")[0]  # Remove fragments and query params
                to_visit.add(clean_link)
        
        # Find and test forms
        forms, tokens = find_forms(r.text, url)
        findings["tokens"].extend(tokens)
        
        if forms:
            for form in forms:
                findings["forms"].append(form)
                
                # Prepare form data for testing
                form_params = {}
                for inp in form["inputs"]:
                    if inp["name"] and inp["type"] not in ["submit", "button"]:
                        form_params[inp["name"]] = inp["value"] or "test"
                
                if form_params:
                    # Test XSS
                    xss_results = test_xss_comprehensive(form["action"], session, form_params, form["method"])
                    findings["xss_vulnerabilities"].extend(xss_results)
                    
                    # Test SQL Injection
                    sql_results = test_sql_injection_comprehensive(form["action"], session, form_params, form["method"])
                    findings["sql_vulnerabilities"].extend(sql_results)
                    
                    # Test Parameter Pollution
                    pollution_results = test_parameter_pollution(form["action"], session, form_params, form["method"])
                    findings["parameter_pollution"].extend(pollution_results)
        
        # Test URL parameters if present
        parsed_url = urlparse(url)
        if parsed_url.query:
            url_params = parse_qs(parsed_url.query)
            flat_params = {k: v[0] if v else "" for k, v in url_params.items()}
            
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            # Test XSS in URL parameters
            xss_results = test_xss_comprehensive(base_url, session, flat_params, "get")
            findings["xss_vulnerabilities"].extend(xss_results)
            
            # Test SQL Injection in URL parameters
            sql_results = test_sql_injection_comprehensive(base_url, session, flat_params, "get")
            findings["sql_vulnerabilities"].extend(sql_results)

    # Check common paths and directories
    print("[*] Testing common paths...")
    findings["open_paths"] = check_common_paths(base, session)
    
    # Test directory traversal
    print("[*] Testing directory traversal...")
    findings["directory_traversal"] = check_directory_traversal(base, session)
    
    return findings

def extract_framework_info(response):
    """Extract framework and technology information from response."""
    frameworks = []
    
    # Check headers for framework indicators
    headers_to_check = ["X-Powered-By", "Server", "X-AspNet-Version", "X-Generator"]
    for header in headers_to_check:
        if header in response.headers:
            frameworks.append(f"{header}: {response.headers[header]}")
    
    # Check HTML content for framework indicators
    framework_patterns = [
        (r"WordPress", "WordPress CMS"),
        (r"Drupal", "Drupal CMS"),
        (r"Joomla", "Joomla CMS"),
        (r"Laravel", "Laravel Framework"),
        (r"Django", "Django Framework"),
        (r"Rails", "Ruby on Rails"),
        (r"Spring", "Spring Framework"),
        (r"ASP\.NET", "ASP.NET Framework"),
        (r"PHP/\d+\.\d+", "PHP Version"),
        (r"jQuery.*\d+\.\d+", "jQuery Library")
    ]
    
    for pattern, name in framework_patterns:
        if re.search(pattern, response.text, re.I):
            frameworks.append(name)
    
    return frameworks

def write_markdown_report(findings, outfile="reports/scan_report.md"):
    lines = []
    lines.append("# Security Scan Report\n")
    
    base_url = findings['pages'][0]['url'] if findings['pages'] else 'N/A'
    lines.append(f"**Target URL**: {base_url}")
    lines.append(f"**Pages Scanned**: {len(findings['pages'])}")
    lines.append(f"**Scan Date**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Executive Summary
    total_high = len([v for v in findings['xss_vulnerabilities'] if v.get('risk') == 'High']) + \
                len([v for v in findings['sql_vulnerabilities'] if v.get('risk') == 'High']) + \
                len([v for v in findings['directory_traversal'] if v.get('risk') == 'High'])
    
    total_medium = len([v for v in findings['parameter_pollution'] if v.get('risk') == 'Medium']) + \
                   len(findings['headers'].get('missing_headers', [])) + \
                   len(findings['headers'].get('cookies', []))
    
    lines.append("## Executive Summary\n")
    lines.append(f"- **High Risk Issues**: {total_high}")
    lines.append(f"- **Medium Risk Issues**: {total_medium}")
    lines.append(f"- **Forms Discovered**: {len(findings['forms'])}")
    lines.append(f"- **Accessible Paths**: {len(findings['open_paths'])}\n")
    
    # Software Stack
    lines.append("## Technology Stack\n")
    stack = findings.get('software_stack', {})
    lines.append(f"- **Web Server**: {stack.get('server', 'Unknown')}")
    lines.append(f"- **Backend Technology**: {stack.get('powered_by', 'Unknown')}")
    if stack.get('framework'):
        lines.append("- **Frameworks/Libraries Detected**:")
        for fw in stack['framework']:
            lines.append(f"  - {fw}")
    lines.append("")
    
    # High Risk Vulnerabilities
    lines.append("## 🔴 High Risk Vulnerabilities\n")
    
    # XSS Vulnerabilities
    if findings['xss_vulnerabilities']:
        lines.append("### Cross-Site Scripting (XSS)\n")
        for vuln in findings['xss_vulnerabilities']:
            lines.append(f"- **URL**: {vuln['url']}")
            lines.append(f"  - **Parameter**: {vuln['parameter']}")
            lines.append(f"  - **Context**: {vuln['context']}")
            lines.append(f"  - **Payload**: `{vuln['payload'][:100]}{'...' if len(vuln['payload']) > 100 else ''}`")
            lines.append("")
    
    # SQL Injection Vulnerabilities
    if findings['sql_vulnerabilities']:
        lines.append("### SQL Injection\n")
        for vuln in findings['sql_vulnerabilities']:
            lines.append(f"- **URL**: {vuln['url']}")
            lines.append(f"  - **Parameter**: {vuln['parameter']}")
            lines.append(f"  - **Type**: {vuln['type']}")
            if 'error_pattern' in vuln:
                lines.append(f"  - **Error Pattern**: {vuln['error_pattern']}")
            if 'response_time' in vuln:
                lines.append(f"  - **Response Time**: {vuln['response_time']:.2f}s")
            lines.append("")
    
    # Directory Traversal
    if findings['directory_traversal']:
        lines.append("### Directory Traversal\n")
        for vuln in findings['directory_traversal']:
            lines.append(f"- **URL**: {vuln['url']}")
            lines.append(f"  - **Parameter**: {vuln['parameter']}")
            lines.append(f"  - **Description**: {vuln['description']}")
            lines.append("")
    
    # Medium Risk Issues
    lines.append("## 🟡 Medium Risk Issues\n")
    
    # Security Headers
    lines.append("### Missing/Weak Security Headers\n")
    for header in findings['headers'].get('missing_headers', []):
        lines.append(f"- **{header['header']}** - {header['issue']} (Risk: {header['risk']})")
    
    for header in findings['headers'].get('weak_headers', []):
        lines.append(f"- **{header['header']}** - {header['issue']}: `{header['value']}` (Risk: {header['risk']})")
    lines.append("")
    
    # Cookie Security
    if findings['headers'].get('cookies'):
        lines.append("### Insecure Cookie Configuration\n")
        for cookie in findings['headers']['cookies']:
            lines.append(f"- **{cookie['name']}**: {cookie['issue']} - {cookie['description']} (Risk: {cookie['risk']})")
        lines.append("")
    
    # Parameter Pollution
    if findings['parameter_pollution']:
        lines.append("### HTTP Parameter Pollution\n")
        for vuln in findings['parameter_pollution']:
            lines.append(f"- **URL**: {vuln['url']}")
            lines.append(f"  - **Parameter**: {vuln['parameter']}")
            lines.append(f"  - **Description**: {vuln['description']}")
            lines.append("")
    
    # Information Disclosure
    lines.append("## Information Disclosure\n")
    
    # Open Paths
    lines.append("### Accessible Paths/Files\n")
    for path in findings['open_paths']:
        risk_emoji = "🔴" if path['risk'] == 'High' else "🟡" if path['risk'] == 'Medium' else "🟢"
        lines.append(f"- {risk_emoji} **{path['path']}** (Status: {path['code']}, Size: {path['size']} bytes)")
    lines.append("")
    
    # Forms Analysis
    if findings['forms']:
        lines.append("##Forms Analysis\n")
        for i, form in enumerate(findings['forms'], 1):
            lines.append(f"### Form {i}\n")
            lines.append(f"- **Action**: {form['action']}")
            lines.append(f"- **Method**: {form['method'].upper()}")
            lines.append(f"- **Parameters**: {len(form['inputs'])}")
            
            input_names = []
            hidden_count = 0
            for inp in form['inputs']:
                if inp.get('hidden'):
                    hidden_count += 1
                elif inp['name']:
                    input_names.append(inp['name'])
            
            if input_names:
                lines.append(f"- **Input Fields**: {', '.join(input_names)}")
            if hidden_count:
                lines.append(f"- **Hidden Fields**: {hidden_count}")
            lines.append("")
    
    # CSRF Protection
    lines.append("##CSRF Protection Analysis\n")
    if findings['tokens']:
        lines.append("### CSRF Tokens Found\n")
        for token in set(findings['tokens']):
            lines.append(f"- {token}")
        lines.append("\n**Status**: CSRF protection likely implemented")
    else:
        lines.append("**Status**: No CSRF tokens detected - forms may be vulnerable to CSRF attacks")
    lines.append("")
    
    # Recommendations
    lines.append("## 🔧 Recommendations\n")
    
    if total_high > 0:
        lines.append("### Immediate Actions Required (High Priority)")
        lines.append("1. **Fix all XSS vulnerabilities** by implementing proper input validation and output encoding")
        lines.append("2. **Address SQL injection flaws** by using parameterized queries/prepared statements")
        lines.append("3. **Restrict directory traversal** by validating file path parameters")
        lines.append("")
    
    lines.append("### Security Hardening (Medium Priority)")
    lines.append("1. **Implement missing security headers** (CSP, HSTS, X-Frame-Options, etc.)")
    lines.append("2. **Configure secure cookie flags** (HttpOnly, Secure, SameSite)")
    lines.append("3. **Remove/restrict access to sensitive files** (.env, config files, backups)")
    lines.append("4. **Implement proper error handling** to prevent information disclosure")
    
    if not findings['tokens']:
        lines.append("5. **Implement CSRF protection** for all forms")
    lines.append("")
    
    # Create reports directory
    os.makedirs("reports", exist_ok=True)
    
    # Write markdown report
    with open(outfile, "w") as fh:
        fh.write("\n".join(lines))
    
    # Convert to HTML with better styling
    html_content = markdown2.markdown("\n".join(lines), extras=['tables', 'code-friendly'])
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px;
            background-color: #f5f5f5; }}
            h1 {{ color: #d32f2f; border-bottom: 3px solid #d32f2f; padding-bottom: 10px; }}
            h2 {{ color: #1976d2; margin-top: 30px; }}
            h3 {{ color: #388e3c; }}
            .high-risk {{ color: #d32f2f; font-weight: bold; }}
            .medium-risk {{ color: #f57c00; font-weight: bold; }}
            .low-risk {{ color: #388e3c; font-weight: bold; }}
            code {{ background-color: #e8e8e8; padding: 2px 4px; border-radius: 3px; }}
            pre {{ background-color: #e8e8e8; padding: 10px; border-radius: 5px; overflow-x: auto; }}
            table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .summary-box {{ 
                background-color: #fff; 
                border: 1px solid #ddd; 
                border-radius: 5px; 
                padding: 15px; 
                margin: 15px 0; 
                box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
            }}
        </style>
    </head>
    <body>
        {html_content}
        <hr>
        <p><em>Generated by Security Scanner</em></p>
    </body>
    </html>
    """
    
    html_outfile = outfile.replace(".md", ".html")
    with open(html_outfile, "w") as fh:
        fh.write(html_template)
    
    print(f"[+] Reports saved to {outfile} and {html_outfile}")

def write_json_report(findings, outfile="reports/scan_results.json"):
    """Write findings to JSON format for programmatic analysis."""
    os.makedirs("reports", exist_ok=True)
    
    # Create a clean JSON structure
    json_data = {
        "scan_metadata": {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "target_url": findings['pages'][0]['url'] if findings['pages'] else 'N/A',
            "pages_scanned": len(findings['pages']),
            "scanner_version": "2.0"
        },
        "vulnerabilities": {
            "high_risk": {
                "xss": findings['xss_vulnerabilities'],
                "sql_injection": findings['sql_vulnerabilities'],
                "directory_traversal": findings['directory_traversal']
            },
            "medium_risk": {
                "missing_headers": findings['headers'].get('missing_headers', []),
                "weak_headers": findings['headers'].get('weak_headers', []),
                "insecure_cookies": findings['headers'].get('cookies', []),
                "parameter_pollution": findings['parameter_pollution']
            }
        },
        "information_disclosure": {
            "accessible_paths": findings['open_paths'],
            "forms": findings['forms'],
            "software_stack": findings.get('software_stack', {})
        },
        "security_measures": {
            "csrf_tokens": findings['tokens']
        }
    }
    
    with open(outfile, 'w') as f:
        json.dump(json_data, f, indent=2)
    
    print(f"[+] JSON report saved to {outfile}")

def print_summary(findings):
    """Print a concise summary to console."""
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    
    # Count vulnerabilities by risk level
    high_risk_count = (
        len([v for v in findings['xss_vulnerabilities'] if v.get('risk') == 'High']) +
        len([v for v in findings['sql_vulnerabilities'] if v.get('risk') == 'High']) +
        len([v for v in findings['directory_traversal'] if v.get('risk') == 'High'])
    )
    
    medium_risk_count = (
        len([v for v in findings['parameter_pollution'] if v.get('risk') == 'Medium']) +
        len(findings['headers'].get('missing_headers', [])) +
        len(findings['headers'].get('weak_headers', [])) +
        len(findings['headers'].get('cookies', []))
    )
    
    print(f"Target: {findings['pages'][0]['url'] if findings['pages'] else 'N/A'}")
    print(f"Pages Scanned: {len(findings['pages'])}")
    print(f"Forms Found: {len(findings['forms'])}")
    print(f"Accessible Paths: {len(findings['open_paths'])}")
    print()
    
    # Risk summary
    if high_risk_count > 0:
        print(f"🔴 HIGH RISK ISSUES: {high_risk_count}")
        if findings['xss_vulnerabilities']:
            print(f"   - XSS Vulnerabilities: {len(findings['xss_vulnerabilities'])}")
        if findings['sql_vulnerabilities']:
            print(f"   - SQL Injection: {len(findings['sql_vulnerabilities'])}")
        if findings['directory_traversal']:
            print(f"   - Directory Traversal: {len(findings['directory_traversal'])}")
    
    if medium_risk_count > 0:
        print(f"🟡 MEDIUM RISK ISSUES: {medium_risk_count}")
        if findings['headers'].get('missing_headers'):
            print(f"   - Missing Security Headers: {len(findings['headers']['missing_headers'])}")
        if findings['headers'].get('cookies'):
            print(f"   - Insecure Cookies: {len(findings['headers']['cookies'])}")
        if findings['parameter_pollution']:
            print(f"   - Parameter Pollution: {len(findings['parameter_pollution'])}")
    
    if high_risk_count == 0 and medium_risk_count == 0:
        print("o major security issues detected!")
    
    # CSRF Protection Status
    print()
    if findings['tokens']:
        print("CSRF Protection: Likely Present")
    else:
        print("CSRF Protection: Not Detected")
    
    # Technology Stack
    stack = findings.get('software_stack', {})
    if stack.get('server', 'Unknown') != 'Unknown':
        print(f" Server: {stack['server']}")
    if stack.get('powered_by', 'Unknown') != 'Unknown':
        print(f"Technology: {stack['powered_by']}")
    
    print("="*60)

def main():
    parser = argparse.ArgumentParser(
        description="web security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        
    )
    
    parser.add_argument("-u", "--url", required=True, 
                       help="Target base URL (e.g., http://127.0.0.1)")
    parser.add_argument("-m", "--max", type=int, default=30, 
                       help="Maximum pages to crawl (default: 30)")
    parser.add_argument("--output", default="reports/scan_report.md",
                       help="Output file path (default: reports/scan_report.md)")
    parser.add_argument("--json-only", action="store_true",
                       help="Only generate JSON report")
    parser.add_argument("--no-html", action="store_true",
                       help="Skip HTML report generation")
    parser.add_argument("--rate-limit", type=float, default=0.8,
                       help="Seconds between requests (default: 0.8)")
    
    args = parser.parse_args()
    
    # Update rate limit if specified
    global RATE_LIMIT
    RATE_LIMIT = args.rate_limit
    
    print("Web Security Scanner")
    
    # Validate URL
    try:
        parsed = urlparse(args.url if args.url.startswith('http') else f'http://{args.url}')
        if not parsed.netloc:
            print("[!] Invalid URL provided")
            return 1
    except Exception as e:
        print(f"[!] URL validation error: {e}")
        return 1
    
    print(f"\n[*] Target: {args.url}")
    print(f"[*] Max pages: {args.max}")
    print(f"[*] Rate limit: {args.rate_limit}s between requests")
    
    # Confirm before starting
    try:
        confirm = input("\n[?] Proceed with scan? (y/N): ").strip().lower()
        if confirm not in ['y', 'yes']:
            print("[*] Scan cancelled")
            return 0
    except KeyboardInterrupt:
        print("\n[*] Scan cancelled")
        return 0
    
    try:
        # Perform the scan
        start_time = time.time()
        findings = analyze_target(args.url, max_pages=args.max)
        scan_duration = time.time() - start_time
        
        print(f"\n[*] Scan completed in {scan_duration:.2f} seconds")
        
        # Print summary
        print_summary(findings)
        
        # Generate reports
        if not args.json_only:
            print(f"\n[*] Generating markdown report...")
            write_markdown_report(findings, args.output)
        
        # Always generate JSON report
        json_path = args.output.replace('.md', '.json')
        write_json_report(findings, json_path)
        
        print("\n[*] Scan complete! Check the reports directory for detailed results.")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"\n[!] Scan error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
