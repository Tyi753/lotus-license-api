import json
import os
from http.server import BaseHTTPRequestHandler
import urllib.request

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            supabase_url = os.environ.get("SUPABASE_URL")
            supabase_key = os.environ.get("SUPABASE_KEY")
            
            if not supabase_url or not supabase_key:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing environment variables"}).encode())
                return
            
            # 查询数据（最多 10000 条）
            query_url = f"{supabase_url}/rest/v1/test_records?order=test_time.desc&limit=10000"
            
            req = urllib.request.Request(query_url)
            req.add_header('apikey', supabase_key)
            req.add_header('Authorization', f'Bearer {supabase_key}')
            req.add_header('Content-Type', 'application/json')
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
            
            # 生成 CSV
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
    
    def do_POST(self):
        self.send_response(405)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"error": "Method not allowed"}).encode())
