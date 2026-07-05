from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import re
import socket
import concurrent.futures
from urllib.parse import urljoin, urlparse
import json

app = Flask(__name__)
CORS(app)

class RealScanner:
    def __init__(self, url):
        self.url = url
        self.domain = urlparse(url).netloc
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
    def check_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.domain.split(':')[0], port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_databases(self):
        findings = []
        try:
            # فحص حقيقي للمنافذ
            db_ports = {3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB', 6379: 'Redis'}
            for port, name in db_ports.items():
                if self.check_port(port):
                    findings.append({
                        'type': f'{name} (Port {port})',
                        'value': f'{self.domain}:{port}',
                        'severity': 'HIGH'
                    })
            
            # فحص المحتوى
            response = self.session.get(self.url, timeout=10, verify=False)
            content = response.text
            
            # كشف اتصالات قواعد البيانات في الكود
            patterns = {
                'MySQL': r'mysql:\/\/[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:\d+\/[a-zA-Z0-9._-]+',
                'MongoDB': r'mongodb:\/\/[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:\d+\/[a-zA-Z0-9._-]+',
                'PostgreSQL': r'postgres:\/\/[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:\d+\/[a-zA-Z0-9._-]+',
                'Redis': r'redis:\/\/[a-zA-Z0-9._-]+:\d+',
            }
            
            for db_type, pattern in patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    if match:
                        findings.append({
                            'type': f'{db_type} Connection',
                            'value': match[:100],
                            'severity': 'CRITICAL'
                        })
        except Exception as e:
            pass
        return findings
    
    def scan_api(self):
        findings = []
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/graphql', '/swagger',
            '/swagger-ui.html', '/swagger.json', '/openapi.json',
            '/api-docs', '/docs', '/wp-json', '/api/users',
            '/api/auth', '/api/login', '/.well-known/openid-configuration'
        ]
        
        def check_api(path):
            try:
                url = urljoin(self.url, path)
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code in [200, 401, 403]:
                    content_type = resp.headers.get('Content-Type', '')
                    is_api = any(x in content_type.lower() for x in ['json', 'xml'])
                    is_swagger = 'swagger' in resp.text.lower() or 'openapi' in resp.text.lower()
                    
                    severity = 'HIGH' if (is_api or is_swagger) else 'MEDIUM'
                    return {
                        'url': url,
                        'status': resp.status_code,
                        'type': content_type,
                        'severity': severity
                    }
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_api, api_paths)
            for result in results:
                if result:
                    findings.append(result)
        
        return findings
    
    def scan_tokens(self):
        findings = []
        try:
            response = self.session.get(self.url, timeout=10, verify=False)
            content = response.text
            
            token_patterns = {
                'AWS Key': r'AKIA[0-9A-Z]{16}',
                'GitHub Token': r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}',
                'Google API': r'AIza[0-9A-Za-z\-_]{35}',
                'JWT Token': r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*',
                'Bearer Token': r'bearer\s+[A-Za-z0-9\-._~+/]+=*',
                'API Key': r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)["\s:=]+["\']([a-zA-Z0-9_\-]{20,})["\']',
                'Private Key': r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----',
                'Stripe Key': r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}',
            }
            
            for token_type, pattern in token_patterns.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match[0] else match[1] if len(match) > 1 else ''
                    if match and len(match) > 10:
                        findings.append({
                            'type': token_type,
                            'value': match[:50] + '...',
                            'severity': 'CRITICAL'
                        })
            
            # فحص ملفات JS
            js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', content)
            for js_file in js_files[:5]:
                try:
                    js_url = urljoin(self.url, js_file)
                    js_resp = self.session.get(js_url, timeout=5, verify=False)
                    for token_type, pattern in token_patterns.items():
                        js_matches = re.findall(pattern, js_resp.text)
                        for match in js_matches[:3]:
                            if isinstance(match, tuple):
                                match = match[0] if match[0] else match[1] if len(match) > 1 else ''
                            if match and len(match) > 10:
                                findings.append({
                                    'type': f'{token_type} (JS)',
                                    'value': match[:50] + '...',
                                    'severity': 'CRITICAL'
                                })
                except:
                    continue
        except Exception as e:
            pass
        return findings
    
    def scan_emails(self):
        findings = []
        try:
            response = self.session.get(self.url, timeout=10, verify=False)
            emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text))
            
            for email in emails:
                severity = 'HIGH' if any(x in email.lower() for x in ['admin', 'root', 'security', 'info']) else 'MEDIUM'
                findings.append({
                    'email': email,
                    'severity': severity
                })
        except:
            pass
        return findings
    
    def scan_admin_panels(self):
        findings = []
        admin_paths = [
            '/admin', '/wp-admin', '/wp-login.php', '/administrator',
            '/phpmyadmin', '/pma', '/dashboard', '/login',
            '/cpanel', '/controlpanel', '/.env', '/.git/config',
            '/config.php', '/wp-config.php', '/backup.zip',
            '/shell.php', '/cmd.php', '/console',
            '/server-status', '/actuator', '/actuator/health'
        ]
        
        def check_admin(path):
            try:
                url = urljoin(self.url, path)
                resp = self.session.get(url, timeout=5, allow_redirects=False, verify=False)
                if resp.status_code in [200, 403]:
                    return {
                        'url': url,
                        'status': resp.status_code,
                        'severity': 'CRITICAL' if resp.status_code == 200 else 'HIGH'
                    }
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_admin, admin_paths)
            for result in results:
                if result:
                    findings.append(result)
        
        return findings
    
    def scan_passwords(self):
        findings = []
        try:
            response = self.session.get(self.url, timeout=10, verify=False)
            content = response.text
            
            patterns = [
                r'(?i)(?:password|passwd|pwd)["\s:=]+["\']([^"\'\s]{4,})["\']',
                r'(?i)(?:DB_PASSWORD|MYSQL_PASSWORD|SECRET_KEY)\s*=\s*([^\s]+)',
                r'mysql:\/\/[^:]+:([^@]+)@',
                r'postgres:\/\/[^:]+:([^@]+)@',
                r'mongodb:\/\/[^:]+:([^@]+)@',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    if match and len(match) > 3:
                        findings.append({
                            'value': match[:30] + '...',
                            'category': 'Plain Text',
                            'severity': 'CRITICAL'
                        })
        except:
            pass
        return findings
    
    def scan_config_files(self):
        findings = []
        config_paths = [
            '.env', '.env.local', '.env.production', '.env.backup',
            'config.php', 'config.yml', 'config.json',
            'wp-config.php', 'wp-config.php.bak', 'wp-config.php.old',
            'backup.zip', 'backup.tar.gz', 'backup.sql', 'dump.sql',
            '.git/config', '.gitignore',
            'Dockerfile', 'docker-compose.yml',
            'error.log', 'debug.log', 'access.log',
            'package.json', 'composer.json'
        ]
        
        def check_config(path):
            try:
                url = urljoin(self.url, path)
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code == 200:
                    return {
                        'url': url,
                        'category': 'Config File',
                        'severity': 'CRITICAL'
                    }
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_config, config_paths)
            for result in results:
                if result:
                    findings.append(result)
        
        return findings
    
    def full_scan(self):
        return {
            'target': self.url,
            'databases': self.scan_databases(),
            'api_endpoints': self.scan_api(),
            'tokens_keys': self.scan_tokens(),
            'emails': self.scan_emails(),
            'admin_panels': self.scan_admin_panels(),
            'passwords': self.scan_passwords(),
            'config_files': self.scan_config_files(),
        }

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    if not url.startswith('http'):
        url = 'https://' + url
    
    try:
        scanner = RealScanner(url)
        results = scanner.full_scan()
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    import urllib3
    urllib3.disable_warnings()
    print('🚀 السيرفر يعمل على: http://localhost:5000')
    app.run(host='0.0.0.0', port=5000, debug=True)