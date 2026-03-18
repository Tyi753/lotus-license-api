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
SIGNATURE_SECRET = "lotus-secret-key-2024-xyz789"  # 签名密钥（客户端需一致）

# ========== 速率限制配置 ==========
request_cache = defaultdict(list)
RATE_LIMIT_WINDOW = 60   # 时间窗口：60 秒
RATE_LIMIT_MAX = 10      # 最大请求数：10 次/分钟

def check_rate_limit(client_ip):
    """检查速率限制"""
    current_time = time.time()
    
    # 清理过期记录
    request_cache[client_ip] = [
        t for t in request_cache[client_ip] 
        if current_time - t < RATE_LIMIT_WINDOW
    ]
    
    # 检查是否超限
    if len(request_cache[client_ip]) >= RATE_LIMIT_MAX:
        return False
    
    # 记录当前请求
    request_cache[client_ip].append(current_time)
    return True

def get_client_ip(headers):
    """获取客户端 IP"""
    for header in ['x-forwarded-for', 'x-real-ip', 'cf-connecting-ip']:
        if header in headers:
            return headers[header].split(',')[0].strip()
    return 'unknown'

def verify_signature(license_key, hwid, timestamp, signature):
    """验证请求签名"""
    # 检查时间戳（防止重放攻击，允许 5 分钟误差）
    current_time = int(time.time())
    if abs(current_time - int(timestamp)) > 300:  # 5 分钟
        return False
    
    # 生成期望的签名
    message = f"{license_key}{hwid}{timestamp}{SIGNATURE_SECRET}"
    expected_signature = hashlib.sha256(message.encode()).hexdigest()
    
    # 对比签名
    return hmac.compare_digest(signature, expected_signature)

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            # ========== 速率限制检查 ==========
            client_ip = get_client_ip(dict(self.headers))
            if not check_rate_limit(client_ip):
                self.send_response(429)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Too many requests, please try again later"}).encode())
                return
            
            # 读取环境变量
            supabase_url = os.environ.get("SUPABASE_URL")
            supabase_key = os.environ.get("SUPABASE_KEY")
            
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
            timestamp = data.get('timestamp')
            signature = data.get('signature')
            
            # ========== 验证签名 ==========
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
            
            # ========== 查询数据库 ==========
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
                self.wfile.write(json.dumps({"error": f"Supabase API error: {e.code}"}).encode())
                return
            
            if not result or len(result) == 0:
                self.send_response(404)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid license key"}).encode())
                return
            
            record = result[0]
            
            # ========== 验证硬件指纹 ==========
            if record.get('hwid') != hwid:
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Hardware mismatch"}).encode())
                return
            
            # ========== 验证状态 ==========
            if record.get('status') != 'active':
                self.send_response(403)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "License blocked"}).encode())
                return
            
            # ========== 返回成功 ==========
            # （移除了更新 last_verify 的操作，避免 400 错误）
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
