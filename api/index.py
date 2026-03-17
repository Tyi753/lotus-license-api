import json
import os
from datetime import datetime, timedelta
from supabase import create_client, Client

# 初始化 Supabase 客户端
supabase_url = os.environ.get("SUPABASE_URL")
supabase_key = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(supabase_url, supabase_key)

def handler(event, context):
    # 只允许 POST 请求
    if event.get('requestContext', {}).get('http', {}).get('method') != 'POST':
        return {"statusCode": 405, "body": json.dumps({"error": "Method not allowed"})}
    
    try:
        # 解析请求体
        body = json.loads(event.get('body', '{}'))
        license_key = body.get('license_key')
        hwid = body.get('hwid')
        
        if not license_key or not hwid:
            return {"statusCode": 400, "body": json.dumps({"error": "Missing license_key or hwid"})}
        
        # 查询数据库
        response = supabase.table("licenses").select("*").eq("license_key", license_key).execute()
        
        if not response.data:
            return {"statusCode": 404, "body": json.dumps({"error": "Invalid license key"})}
        
        record = response.data[0]
        
        # 验证硬件指纹
        if record['hwid'] != hwid:
            return {"statusCode": 403, "body": json.dumps({"error": "Hardware mismatch"})}
        
        # 验证状态
        if record['status'] != 'active':
            return {"statusCode": 403, "body": json.dumps({"error": "License blocked"})}
        
        # 更新最后验证时间
        supabase.table("licenses").update({"last_verify": datetime.utcnow().isoformat()}).eq("license_key", license_key).execute()
        
        return {"statusCode": 200, "body": json.dumps({"status": "valid", "message": "License verified"})}
        
    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
