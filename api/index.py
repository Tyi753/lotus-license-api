import json
import os
from datetime import datetime
from http.server import BaseHTTPRequestHandler
import urllib.request
import urllib.error

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            # 读取环境变量
            supabase_url = os.environ.get("SUPABASE_URL")
            supabase_key = os.environ.get("SUPABASE_KEY")
            
            # 检查环境变量
            if not supabase_url or not supabase_key:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing environment variables"}).encode())
                return
            
            # 读取请求体
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body)
            
            license_key = data.get('license_key')
            hwid = data.get('hwid')
            
            if not license_key or not hwid:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing license_key or hwid"}).encode())
                return
            
            # 使用 HTTP 直接请求 Supabase API
            query_url = f"{supabase_url}/rest/v1/licenses?license_key=eq.{license_key}"
            
            req = urllib.request.Request(query_url)
            req.add_header('apikey', supabase_key)
            req.add_header('Authorization', f'Bearer {supabase_key}')
            req.add_header('Content-Type', 'application/json')
            
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    result = json.loads(response.read().decode())
            except urllib.error.HTTPError as e:
                error_body = e.read().decode()
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Supabase API error: {e.code} - {error_body}"}).encode())
                return
            
            if not result or len(result) == 0:
                self.send_response(404)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid license key"}).encode())
                return
            
            record = result[0]
            
            # 验证硬件指纹
            if record.get('hwid') != hwid:
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Hardware mismatch"}).encode())
                return
            
            # 验证状态
            if record.get('status') != 'active':
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "License blocked"}).encode())
                return
            
            # 更新最后验证时间（可选）
            # update_url = f"{supabase_url}/rest/v1/licenses"
            # update_data = json.dumps({"last_verify": datetime.utcnow().isoformat()}).encode()
            # update_req = urllib.request.Request(update_url, data=update_data, method='PATCH')
            # update_req.add_header('apikey', supabase_key)
            # update_req.add_header('Authorization', f'Bearer {supabase_key}')
            # update_req.add_header('Content-Type', 'application/json')
            # update_req.add_header('Prefer', 'return=minimal')
            # urllib.request.urlopen(update_req, timeout=10)
            
            # 返回成功
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "valid", "message": "License verified"}).encode())
            
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())
    
    def do_GET(self):
        self.send_response(405)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"error": "Method not allowed"}).encode())
