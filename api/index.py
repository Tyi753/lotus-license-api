import json
import os
from datetime import datetime
from http.server import BaseHTTPRequestHandler
import urllib.request
import urllib.error
import hmac
import hashlib
import time
from collections import defaultdict

# ========== 安全配置 ==========
SIGNATURE_SECRET = "lotus-secret-key-2024-xyz789"

# ========== 速率限制配置 ==========
request_cache = defaultdict(list)
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 10

def check_rate_limit(client_ip):
    current_time = time.time()
    request_cache[client_ip] = [
        t for t in request_cache[client_ip] 
        if current_time - t < RATE_LIMIT_WINDOW
    ]
    if len(request_cache[client_ip]) >= RATE_LIMIT_MAX:
        return False
    request_cache[client_ip].append(current_time)
    return True

def get_client_ip(headers):
    for header in ['x-forwarded-for', 'x-real-ip', 'cf-connecting-ip']:
        if header in headers:
            return headers[header].split(',')[0].strip()
    return 'unknown'

def verify_signature(license_key, hwid, timestamp, signature):
    current_time = int(time.time())
    if abs(current_time - int(timestamp)) > 300:
        return False
    message = f"{license_key}{hwid}{timestamp}{SIGNATURE_SECRET}"
    expected_signature = hashlib.sha256(message.encode()).hexdigest()
    return hmac.compare_digest(signature, expected_signature)

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # 处理导出请求
        if self.path == '/api/export' or self.path == '/api/export/':
            self.handle_export()
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Not found"}).encode())
    
    def do_POST(self):
        # 处理验证请求
        if self.path == '/api/verify' or self.path == '/api/verify/':
            self.handle_verify()
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Not found"}).encode())
    
    def handle_verify(self):
        try:
            client_ip = get_client_ip(dict(self.headers))
            if not check_rate_limit(client_ip):
                self.send_response(429)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Too many requests"}).encode())
                return
            
            supabase_url = os.environ.get("SUPABASE_URL")
            supabase_key = os.environ.get("SUPABASE_KEY")
            
            if not supabase_url or not supabase_key:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing environment variables"}).encode())
                return
            
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body)
            
            license_key = data.get('license_key')
            hwid = data.get('hwid')
            timestamp = data.get('timestamp')
            signature = data.get('signature')
            
            if not timestamp or not signature:
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing signature"}).encode())
                return
            
            if not verify_signature(license_key, hwid, timestamp, signature):
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid signature"}).encode())
                return
            
            if not license_key or not hwid:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing license_key or hwid"}).encode())
                return
            
            query_url = f"{supabase_url}/rest/v1/licenses?license_key=eq.{license_key}"
            req = urllib.request.Request(query_url)
            req.add_header('apikey', supabase_key)
            req.add_header('Authorization', f'Bearer {supabase_key}')
            req.add_header('Content-Type', 'application/json')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode())
            
            if not result or len(result) == 0:
                self.send_response(404)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid license key"}).encode())
                return
            
            record = result[0]
            
            if record.get('hwid') != hwid:
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Hardware mismatch"}).encode())
                return
            
            if record.get('status') != 'active':
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "License blocked"}).encode())
                return
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "valid", "message": "License verified"}).encode())
            
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())
    
    def handle_export(self):
        try:
            supabase_url = os.environ.get("SUPABASE_URL")
            supabase_key = os.environ.get("SUPABASE_KEY")
            
            if not supabase_url or not supabase_key:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing environment variables"}).encode())
                return
            
            query_url = f"{supabase_url}/rest/v1/test_records?order=test_time.desc&limit=10000"
            req = urllib.request.Request(query_url)
            req.add_header('apikey', supabase_key)
            req.add_header('Authorization', f'Bearer {supabase_key}')
            req.add_header('Content-Type', 'application/json')
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
            
            csv_content = "测试时间，SN 码，设备名称，MAC 地址，信号强度，固件版本，电池电量，伺服校准，测试结果，不合格项\n"
            for row in data:
                result = "合格" if row.get('is_valid') else "不合格"
                csv_content += f"{row.get('test_time','')},{row.get('sn_code','')},{row.get('device_name','')},{row.get('mac_address','')},{row.get('rssi','')},{row.get('firmware_version','')},{row.get('battery_level','')},{row.get('servo_calibration','')},{result},{row.get('errors','')}\n"
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('Content-Disposition', 'attachment; filename="lotus_test_records.csv"')
            self.end_headers()
            self.wfile.write(csv_content.encode('utf-8-sig'))
            
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())
