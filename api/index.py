import json
import os
from datetime import datetime
from http.server import BaseHTTPRequestHandler
from supabase import create_client

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            # 读取环境变量
            supabase_url = os.environ.get("SUPABASE_URL")
            supabase_key = os.environ.get("SUPABASE_KEY")
            
            # 调试：检查环境变量
            if not supabase_url:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "SUPABASE_URL is missing"}).encode())
                return
            
            if not supabase_key:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "SUPABASE_KEY is missing"}).encode())
                return
            
            # 调试：显示密钥的前几位（生产环境不要这样做，仅用于调试）
            # print(f"DEBUG: URL={supabase_url[:20]}...")
            # print(f"DEBUG: Key={supabase_key[:20]}...")
            
            # 初始化 Supabase 客户端
            supabase = create_client(supabase_url, supabase_key)
            
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
            
            # 查询数据库
            response = supabase.table("licenses").select("*").eq("license_key", license_key).execute()
            
            if not response.data:
                self.send_response(404)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid license key"}).encode())
                return
            
            record = response.data[0]
            
            # 验证硬件指纹
            if record['hwid'] != hwid:
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Hardware mismatch"}).encode())
                return
            
            # 验证状态
            if record['status'] != 'active':
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "License blocked"}).encode())
                return
            
            # 更新最后验证时间
            supabase.table("licenses").update({"last_verify": datetime.utcnow().isoformat()}).eq("license_key", license_key).execute()
            
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
