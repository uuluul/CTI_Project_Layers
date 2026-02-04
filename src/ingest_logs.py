import time
import os
from datetime import datetime, timezone
# --- 新增這兩行 ---
from dotenv import load_dotenv
load_dotenv()  # <--- 這行非常重要！沒有它就讀不到密碼
# ----------------
from opensearchpy import OpenSearch
from .llm_client import LLMClient

# 初始化
llm = LLMClient()
client = OpenSearch(
    hosts=[{'host': 'localhost', 'port': 9200}],
    http_compress=True,
    use_ssl=False
)
index_name = "security-logs-knn"

# --- 模擬一些「正常的」Log (Baseline) ---
normal_logs = [
    "User admin logged in successfully from IP 192.168.1.5 via SSH.",
    "System scheduled backup started at 02:00 AM.",
    "File server synced 500 files to cloud storage.",
    "User alice access HR database for payroll report.",
    "Antivirus scan completed. No threats found.",
    "Network interface eth0 up, speed 1000Mbps.",
    "Web server apache2 restarted successfully.",
    "Database connection pool initialized with 10 connections."
]

def ingest_data():
    print(f"🚀 開始匯入 {len(normal_logs)} 筆正常 Log 作為基準...")
    
    for log_text in normal_logs:
        try:
            # 1. 呼叫 OpenAI 取得向量
            print(f"正在向量化: {log_text[:30]}...")
            embedding = llm.get_embedding(log_text)
            
            # 2. 準備要存入的資料
            doc = {
                "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                "log_text": log_text,
                "log_vector": embedding
            }
            
            # 3. 寫入 OpenSearch
            client.index(index=index_name, body=doc)
            
        except Exception as e:
            print(f"❌ 錯誤: {e}")
            
    # 強制重新整理
    client.indices.refresh(index=index_name)
    print("✅ 所有 Log 匯入完成！")

if __name__ == "__main__":
    ingest_data()